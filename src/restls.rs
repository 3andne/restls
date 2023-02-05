use anyhow::{anyhow, Context, Result};
use futures_util::stream::StreamExt;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::{io::Cursor, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    select,
};
use tokio_util::codec::Decoder;
use tracing::debug;
type HmacSha1 = Hmac<Sha1>;

use crate::{
    args::Opt,
    client_hello::ClientHello,
    common::{RECORD_APPLICATION_DATA, RECORD_CCS, RECORD_HANDSHAKE, REQUIRED_HMAC_LEN},
    server_hello::ServerHello,
    utils::{copy_bidirectional, copy_bidirectional_fallback, xor_bytes, TLSCodec, TLSStream},
};

struct TryHandshake {}

impl TryHandshake {
    async fn read_from_stream(&self, stream: &mut TLSStream) -> Result<u8> {
        stream
            .next()
            .await
            .ok_or_else(|| anyhow!("unexpected eof"))?
    }

    async fn try_read_client_hello(&self, inbound: &mut TLSStream) -> Result<ClientHello> {
        let rtype = self
            .read_from_stream(inbound)
            .await
            .context("failed to read client hello: ")?;
        if rtype != RECORD_HANDSHAKE {
            return Err(anyhow!(
                "reject: incorrect record type for client hello, actual: {}",
                rtype
            ));
        }
        let mut cursor = Cursor::new(inbound.codec().buf.as_slice());
        ClientHello::parse(&mut cursor).context("unable to parse client hello: ")
    }

    async fn try_read_server_hello(&mut self, outbound: &mut TLSStream) -> Result<ServerHello> {
        let rtype = self
            .read_from_stream(outbound)
            .await
            .context("failed to read server hello: ")?;
        if rtype != RECORD_HANDSHAKE {
            return Err(anyhow!(
                "reject: incorrect record type for client hello, actual: {}",
                rtype
            ));
        }
        let mut cursor = Cursor::new(outbound.codec().buf.as_slice());
        ServerHello::parse(&mut cursor).context("unable to parse client hello: ")
    }

    async fn try_read_tls13_till_first_0x17(
        &mut self,
        server_hello: &ServerHello,
        restls_password: &[u8],
        outbound: &mut TLSStream,
        inbound: &mut TLSStream,
    ) -> Result<()> {
        let mut ccs_from_server = false;
        loop {
            let rtype = self.read_from_stream(outbound).await?;

            match rtype {
                RECORD_CCS if !ccs_from_server => {
                    ccs_from_server = true;
                }
                RECORD_APPLICATION_DATA if ccs_from_server => {
                    break;
                }
                _ => {
                    return Err(anyhow!(
                    "reject: incorrect record type, expected 1 CCS or Application Data, actual {rtype}",
                ))
                }
            }
            self.relay_to(inbound, outbound).await?;
        }
        let mut hasher =
            HmacSha1::new_from_slice(restls_password).expect("sha1 should take key of any size");
        hasher.update(&server_hello.server_random);
        let secret = hasher.finalize().into_bytes();
        debug!("tls13 server challenge {:?}", &secret[..REQUIRED_HMAC_LEN]);
        xor_bytes(
            &secret[..REQUIRED_HMAC_LEN],
            &mut outbound.codec_mut().buf[5..],
        );
        Ok(())
    }

    async fn try_read_till_client_application_data(
        &mut self,
        expect_application_data: usize,
        outbound: &mut TLSStream,
        inbound: &mut TLSStream,
    ) -> Result<()> {
        let mut seen_client_application_data = 0;
        let mut ccs_from_client = false;
        loop {
            select! {
                rtype = self.read_from_stream(inbound) => {
                    let rtype = rtype?;
                    match rtype {
                        RECORD_CCS if !ccs_from_client => {
                            ccs_from_client = true;
                        }
                        RECORD_APPLICATION_DATA if ccs_from_client => {
                            seen_client_application_data += 1;
                            if seen_client_application_data == expect_application_data {
                                break;
                            }
                        }
                        _ => {
                            return Err(anyhow!(
                                "reject: incorrect record type, expected 1 CCS or Application Data, actual {rtype}",
                            ));
                        }
                    }
                    self.relay_to(outbound, inbound).await?;
                }
                _ = self.read_from_stream(outbound) => {
                    self.relay_to(inbound, outbound).await?;
                }
            }
        }
        Ok(())
    }

    fn check_tls_13_session_id(
        &self,
        client_hello: &ClientHello,
        restls_password: &[u8],
    ) -> Result<()> {
        let mut hasher =
            HmacSha1::new_from_slice(restls_password).expect("sha1 should take key of any size");
        hasher.update(&client_hello.key_share);
        hasher.update(&client_hello.psk);
        let res_raw = hasher.finalize();
        let res = res_raw.into_bytes();
        let expect = &res[..REQUIRED_HMAC_LEN];
        let actual = &client_hello.session_id.get()[..REQUIRED_HMAC_LEN];
        // we don't need constant time comparison since
        // that's not noticeable compared to network delay.
        if expect == actual {
            Ok(())
        } else {
            Err(anyhow!(
                "reject: incorrect session id, expect: {:?}, actual {:?}",
                expect,
                actual
            ))
        }
    }

    fn check_tls_13_application_data_auth(
        &self,
        server_hello: &ServerHello,
        restls_password: &[u8],
        in_buf: &[u8],
    ) -> Result<()> {
        let mut hasher =
            HmacSha1::new_from_slice(restls_password).expect("sha1 should take key of any size");
        hasher.update(&server_hello.server_random);
        hasher.update(&server_hello.server_random);
        let res = hasher.finalize().into_bytes();
        let expect = &res[..REQUIRED_HMAC_LEN];
        let application_data = &in_buf[5..];
        if application_data.len() < REQUIRED_HMAC_LEN {
            return Err(anyhow!(
                "reject: application data too short to contain an auth header"
            ));
        }
        let actual = &application_data[..REQUIRED_HMAC_LEN];
        if expect == actual {
            debug!("tls13 challenge responded");
            Ok(())
        } else {
            Err(anyhow!(
                "reject: incorrect application auth header, expect: {:?}, actual {:?}",
                expect,
                actual
            ))
        }
    }

    async fn relay_to(
        &mut self,
        to_stream: &mut TLSStream,
        from_stream: &mut TLSStream,
    ) -> Result<()> {
        let res = match to_stream
            .get_mut()
            .write_all(&from_stream.codec().buf)
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => Err(e.into()),
        };
        from_stream.codec_mut().reset();
        res
    }

    async fn try_handshake(
        &mut self,
        options: &Opt,
        outbound: &mut TLSStream,
        inbound: &mut TLSStream,
    ) -> Result<usize> {
        let client_hello = self.try_read_client_hello(inbound).await?;
        self.relay_to(outbound, inbound).await?;

        let server_hello = self.try_read_server_hello(outbound).await?;
        self.relay_to(inbound, outbound).await?;

        if server_hello.is_tls_13 {
            let password = options.password.as_bytes();
            self.check_tls_13_session_id(&client_hello, password)?;
            self.try_read_tls13_till_first_0x17(&server_hello, password, outbound, inbound)
                .await?;
            debug!("sending challenge to client");
            self.relay_to(inbound, outbound).await?;
            self.try_read_till_client_application_data(2, outbound, inbound)
                .await?;
            self.check_tls_13_application_data_auth(&server_hello, password, &inbound.codec().buf)?;
            Ok(REQUIRED_HMAC_LEN + 5)
        } else {
            unimplemented!("TLS 1.2 remains a work in progress");
            // Ok(5)
        }
    }
}

pub async fn handle(options: Arc<Opt>, inbound: TcpStream) -> Result<()> {
    let codec_in = TLSCodec::new();
    let mut outbound = codec_in.framed(
        TcpStream::connect(&options.server_hostname)
            .await
            .context("cannot connect to outbound".to_owned() + &options.server_hostname)?,
    );

    let codec_out = TLSCodec::new();
    let mut inbound = codec_out.framed(inbound);
    let mut try_handshake = TryHandshake {};
    match try_handshake
        .try_handshake(&options, &mut outbound, &mut inbound)
        .await
    {
        Ok(discard) => {
            let outbound_proxy = TcpStream::connect(&options.forward_to).await?;
            copy_bidirectional(inbound, outbound_proxy, discard).await?;
        }
        Err(e) => {
            tracing::error!("handshake failed: {}", e);
            copy_bidirectional_fallback(inbound, outbound).await?;
        }
    }
    Ok(())
}

pub async fn start(options: Arc<Opt>) -> Result<()> {
    let listener = TcpListener::bind(&options.listen).await?;

    tracing::info!(
        "Restls server started as {} on {}, forwarding to {}",
        options.server_hostname,
        options.listen,
        options.forward_to,
    );
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("failed to accept inbound stream")?;
        let options = options.clone();
        tokio::spawn(async move { handle(options, stream).await });
    }
}
