use anyhow::{anyhow, Result};
use bytes::Buf;
use hmac::Mac;
use std::io::Cursor;

use crate::{
    client_hello::ClientHello,
    common::{HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, RECORD_HANDSHAKE, RESTLS_HANDSHAKE_HMAC_LEN},
    utils::HmacSha1,
};

pub struct ClientKeyExchange {}

impl ClientKeyExchange {
    pub(crate) fn check(
        buf: &mut Cursor<&[u8]>,
        restls_password: &[u8],
        client_hello: &ClientHello,
    ) -> Result<()> {
        assert_eq!(buf.get_u8(), RECORD_HANDSHAKE);
        buf.advance(4);
        let htype = buf.get_u8();
        if htype != HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE {
            return Err(anyhow!("expecting handshake type 0x10, got {}", htype));
        }
        buf.advance(4);

        let mut hasher = HmacSha1::new_from_slice(restls_password).expect("unexpected");
        hasher.update(buf.chunk());
        let actual_hash = hasher.finalize().into_bytes();

        if &client_hello.session_id[..RESTLS_HANDSHAKE_HMAC_LEN] != &actual_hash[..RESTLS_HANDSHAKE_HMAC_LEN] {
            Err(anyhow!("reject: tls 1.2 client pub key mismatched"))
        } else {
            Ok(())
        }
    }
}
