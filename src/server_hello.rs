use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut};
use std::io::Cursor;
use tracing::debug;

use crate::{
    common::{
        EXTENSION_KEY_SHARE, EXTENSION_SUPPORTED_VERSIONS, HANDSHAKE_TYPE_SERVER_HELLO,
        HELLO_RETRY_RANDOM, TLS12_GCM_CIPHER_SUITES,
    },
    utils::{extend_from_length_prefixed, skip_length_padded, u16_length_prefixed},
};

pub(crate) struct ServerHello {
    pub(crate) is_tls13: bool,
    pub(crate) server_random: [u8; 32],
    pub(crate) _key_share: Vec<u8>,
    pub(crate) is_tls12_gcm: bool,
}

impl ServerHello {
    fn read_supported_version<T: Buf>(buf: &mut T) -> bool {
        let mut client_supports_tls_13 = false;
        u16_length_prefixed(buf, |mut extension| {
            client_supports_tls_13 = extension.get_u16().to_be_bytes() == [03, 04];
            Ok(())
        })
        .unwrap(); // todo: check this for server
        client_supports_tls_13
    }

    fn read_key_share<T: Buf>(buf: &mut T) -> Vec<u8> {
        let mut key_share = Vec::new();
        u16_length_prefixed(buf, |mut key_share_section| {
            key_share.reserve_exact(key_share_section.remaining());
            key_share.put_u16(key_share_section.get_u16()); // skip key_share group
            extend_from_length_prefixed::<2, _>(&mut key_share_section, &mut key_share)?;
            Ok(())
        })
        .unwrap(); // todo: check this for server
        key_share
    }

    pub(crate) fn parse(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        let htype = buf.get_u8();
        if htype != HANDSHAKE_TYPE_SERVER_HELLO {
            return Err(anyhow!(
                "reject: incorrect handshake type, expect {}, got {}",
                HANDSHAKE_TYPE_SERVER_HELLO,
                htype
            ));
        }
        buf.advance(3 + 2); // skip len + version

        let mut server_random = [0; 32];
        buf.copy_to_slice(&mut server_random);
        debug!("server random: {:?}", server_random);
        if server_random == HELLO_RETRY_RANDOM {
            return Err(anyhow!("reject: we don't allow a Hello Retry Request"));
        }
        // todo
        skip_length_padded::<1, _>(buf).unwrap(); // skip session id
        let cipher_suite = buf.get_u16();
        buf.advance(1 + 2); // skip cipher suite + compression method + Extensions Length
        let mut is_tls13 = false;
        let mut key_share = Vec::new();
        while buf.has_remaining() {
            let ext = buf.get_u16();
            match ext {
                EXTENSION_SUPPORTED_VERSIONS => {
                    is_tls13 = Self::read_supported_version(buf);
                }
                EXTENSION_KEY_SHARE => {
                    key_share = Self::read_key_share(buf);
                }
                _ => {
                    skip_length_padded::<2, _>(buf).unwrap(); // todo
                }
            }
        }
        Ok(ServerHello {
            is_tls13,
            server_random,
            _key_share: key_share,
            is_tls12_gcm: TLS12_GCM_CIPHER_SUITES.contains(&cipher_suite),
        })
    }
}
