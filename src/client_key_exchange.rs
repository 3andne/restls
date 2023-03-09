use anyhow::{anyhow, Result};
use blake3::Hasher;
use bytes::Buf;
use hmac::Mac;
use std::io::Cursor;

use crate::{
    client_hello::ClientHello,
    common::{
        curve_id_to_index, CLIENT_AUTH_LAYOUT3, CLIENT_AUTH_LAYOUT4,
        HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, RECORD_HANDSHAKE,
    },
};

pub struct ClientKeyExchange {}

impl ClientKeyExchange {
    pub(crate) fn check(
        buf: &mut Cursor<&[u8]>,
        client_hello: &ClientHello,
        curve: usize,
        mut hasher: Hasher,
    ) -> Result<()> {
        assert_eq!(buf.get_u8(), RECORD_HANDSHAKE);
        buf.advance(4);
        let htype = buf.get_u8();
        if htype != HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE {
            return Err(anyhow!("expecting handshake type 0x10, got {}", htype));
        }
        buf.advance(4);

        hasher.update(buf.chunk());
        let actual_hash = hasher.finalize().into_bytes();

        let curve_index = curve_id_to_index(curve)?;
        let range = if client_hello.session_ticket.len() > 0 {
            CLIENT_AUTH_LAYOUT4[curve_index]..CLIENT_AUTH_LAYOUT4[curve_index + 1]
        } else {
            CLIENT_AUTH_LAYOUT3[curve_index]..CLIENT_AUTH_LAYOUT3[curve_index + 1]
        };
        let hash_len = range.len();
        if &client_hello.session_id[range] != &actual_hash[..hash_len] {
            Err(anyhow!(
                "reject: tls 1.2 client pub key mismatched, expect {:?}, actual {:?}, key {:?}",
                &client_hello.session_id,
                &actual_hash,
                buf.chunk()
            ))
        } else {
            Ok(())
        }
    }
}
