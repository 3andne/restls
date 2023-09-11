use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut};
use std::io::Cursor;
use tracing::debug;

use crate::{
    common::{
        EXTENSION_KEY_SHARE, EXTENSION_PRE_SHARED_KEY, EXTENSION_SESSION_TICKET,
        EXTENSION_SUPPORTED_VERSIONS, HANDSHAKE_TYPE_CLIENT_HELLO, REQUIRED_SESSION_ID_LEN,
    },
    utils::{
        extend_from_length_prefixed, read_length_padded, skip_length_padded, u16_length_prefixed,
        u8_length_prefixed, CheckedAdvance,
    },
};

pub(crate) struct ClientHello {
    pub(crate) _client_random: [u8; 32],
    pub(crate) session_id: [u8; 32],
    pub(crate) key_share: Vec<u8>,
    pub(crate) psk: Vec<u8>,
    pub(crate) session_ticket: Vec<u8>,
}

impl ClientHello {
    fn read_supported_version<T: Buf>(buf: &mut T) -> Result<bool> {
        let mut client_supports_tls_13 = false;
        u16_length_prefixed(buf, |mut extension| {
            u8_length_prefixed(&mut extension, |mut versions| {
                while versions.has_remaining() {
                    if versions.remaining() < 2 {
                        return Err(anyhow!(
                            "read_supported_version failed: versions.remaining() < 2"
                        ));
                    }
                    if versions.get_u16().to_be_bytes() == [03, 04] {
                        client_supports_tls_13 = true;
                        break;
                    }
                }
                Ok(())
            })
        })?;
        Ok(client_supports_tls_13)
    }

    fn read_psk<T: Buf>(buf: &mut T) -> Result<Vec<u8>> {
        let mut psk = Vec::new();
        u16_length_prefixed(buf, |mut extension| {
            u16_length_prefixed(&mut extension, |mut psk_section| {
                psk.reserve_exact(psk_section.remaining());
                while psk_section.has_remaining() {
                    extend_from_length_prefixed::<2, _>(&mut psk_section, &mut psk)?;
                    psk_section.checked_advance(4, "read_psk failed to skip psk age")?;
                    // +4 to skip psk age
                }
                Ok(())
            })
        })?;
        Ok(psk)
    }

    fn read_key_share<T: Buf>(buf: &mut T) -> Result<Vec<u8>> {
        let mut key_share = Vec::new();
        u16_length_prefixed(buf, |mut extension| {
            u16_length_prefixed(&mut extension, |mut key_share_section| {
                key_share.reserve_exact(key_share_section.remaining());
                while key_share_section.has_remaining() {
                    if key_share_section.remaining() < 2 {
                        return Err(anyhow!("read_key_share failed to skip key_share group"));
                    }
                    key_share.put_u16(key_share_section.get_u16()); // skip key_share group
                    extend_from_length_prefixed::<2, _>(&mut key_share_section, &mut key_share)?;
                }
                Ok(())
            })
        })?;
        Ok(key_share)
    }

    pub(crate) fn parse(buf: &mut Cursor<&[u8]>, id: usize) -> Result<ClientHello> {
        debug!(
            "[{}]parsing client hello: {} {:?}",
            id,
            buf.remaining(),
            buf.chunk()
        );

        buf.advance(5); // record header
        let mut _client_random = [0; 32];
        let htype = buf.get_u8();
        if htype != HANDSHAKE_TYPE_CLIENT_HELLO {
            return Err(anyhow!(
                "reject: incorrect handshake type, expect {}, got {}",
                HANDSHAKE_TYPE_CLIENT_HELLO,
                htype
            ));
        }
        buf.advance(3); // len
        buf.advance(2); // version
        buf.copy_to_slice(&mut _client_random); // client random

        let mut session_id = [0; 32];
        let session_id_len = read_length_padded::<1, _>(buf, &mut session_id)?; // session id
        debug!("session id: {:?}", session_id);
        if session_id_len != REQUIRED_SESSION_ID_LEN {
            return Err(anyhow!("reject: session id should be exactly 32 bytes"));
        }

        skip_length_padded::<2, _>(buf)?; // cipher suites
        skip_length_padded::<1, _>(buf)?; // compression methods

        let mut session_ticket = Vec::new();
        let mut client_supports_tls_13 = false;
        let mut psk = Vec::new();
        let mut key_share = Vec::new();
        u16_length_prefixed(buf, |mut ext_section| {
            while ext_section.has_remaining() {
                let ext = ext_section.get_u16();
                match ext {
                    EXTENSION_SESSION_TICKET => {
                        extend_from_length_prefixed::<2, _>(&mut ext_section, &mut session_ticket)?;
                        debug!("session_ticket: {:?}", session_ticket);
                    }
                    EXTENSION_SUPPORTED_VERSIONS => {
                        client_supports_tls_13 = Self::read_supported_version(&mut ext_section)?;
                    }
                    EXTENSION_PRE_SHARED_KEY => {
                        psk = Self::read_psk(&mut ext_section)?;
                        debug!("psk: {:?}", psk);
                    }
                    EXTENSION_KEY_SHARE => {
                        key_share = Self::read_key_share(&mut ext_section)?;
                        debug!("client key_share {:?}", key_share);
                    }
                    _ => {
                        skip_length_padded::<2, _>(&mut ext_section)?;
                    }
                }
            }
            Ok(())
        })?;

        if !client_supports_tls_13 {
            return Err(anyhow!("reject: client must support tls 1.3"));
        }
        Ok(ClientHello {
            _client_random,
            session_id,
            key_share,
            psk,
            session_ticket,
        })
    }
}
