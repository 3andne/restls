use anyhow::{anyhow, Context, Result};
use futures_util::stream::StreamExt;
use hmac::Mac;
use std::{io::Cursor, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    select,
};
use tokio_util::codec::Decoder;
use tracing::debug;

use crate::{
    args::Opt,
    client_hello::ClientHello,
    client_key_exchange::ClientKeyExchange,
    common::{
        RECORD_APPLICATION_DATA, RECORD_CCS, RECORD_HANDSHAKE, RESTLS_APPDATA_HMAC_LEN,
        RESTLS_HANDSHAKE_HMAC_LEN,
    },
    server_hello::ServerHello,
    utils::{
        copy_bidirectional, copy_bidirectional_fallback, xor_bytes, HmacSha1, TLSCodec, TLSStream,
    },
};

#[derive(Debug)]
enum TLS12Flow {
    Initial,
    CKEVerified,
    FullHandshakeClientCCS,
    ResumeClientCCS,
    FullHandshakeServerCCS,
    ResumeServerCCS,
    Client0x17,
}

impl TLS12Flow {
    fn ccs_from_client(&mut self) -> Result<()> {
        match self {
            TLS12Flow::CKEVerified => {
                *self = TLS12Flow::FullHandshakeClientCCS;
                Ok(())
            }
            TLS12Flow::ResumeServerCCS => {
                *self = TLS12Flow::ResumeClientCCS;
                Ok(())
            }
            _ => Err(anyhow!(
                "reject: invalid flow, expect CKEVerified or ResumeServerCCS, actual: {:?}",
                self
            )),
        }
    }

    fn ccs_from_server(&mut self) -> Result<()> {
        match self {
            TLS12Flow::Initial => {
                *self = TLS12Flow::ResumeServerCCS;
                Ok(())
            }
            TLS12Flow::FullHandshakeClientCCS => {
                *self = TLS12Flow::FullHandshakeServerCCS;
                Ok(())
            }
            _ => Err(anyhow!(
                "reject: invalid flow, expect Initial or FullHandshakeClientCCS, actual: {:?}",
                self
            )),
        }
    }

    fn cke_verified(&mut self) -> Result<()> {
        match self {
            TLS12Flow::Initial => {
                *self = TLS12Flow::CKEVerified;
                Ok(())
            }
            _ => Err(anyhow!(
                "reject: invalid flow, expect Initial, actual: {:?}",
                self
            )),
        }
    }

    fn client_0x17(&mut self) -> Result<()> {
        use TLS12Flow::*;
        match self {
            FullHandshakeServerCCS | ResumeClientCCS => {
                *self = TLS12Flow::Client0x17;
                Ok(())
            }
            _ => Err(anyhow!(
                "reject: invalid flow, expect FullHandshakeServerCCS | ResumeClientCCS, actual: {:?}",
                self
            )),
        }
    }

    fn is_ccs_from_server(&self) -> bool {
        match self {
            TLS12Flow::FullHandshakeServerCCS | TLS12Flow::ResumeServerCCS => true,
            _ => false,
        }
    }

    fn is_resume_ccs_from_client(&self) -> bool {
        match self {
            TLS12Flow::ResumeClientCCS => true,
            _ => false,
        }
    }

    fn is_resume(&self) -> bool {
        use TLS12Flow::*;

        match self {
            ResumeClientCCS | ResumeServerCCS => true,
            _ => false,
        }
    }

    fn expect_cke(&self) -> bool {
        match self {
            TLS12Flow::Initial => true,
            _ => false,
        }
    }

    fn is_client_0x17(&self) -> bool {
        match self {
            TLS12Flow::Client0x17 => true,
            _ => false,
        }
    }
}

struct TryHandshake<'a> {
    client_hello: Option<ClientHello>,
    server_hello: Option<ServerHello>,
    client_finished: Vec<u8>,
    restls_password: &'a [u8],
}

impl<'a> TryHandshake<'a> {
    async fn read_from_stream(&self, stream: &mut TLSStream) -> Result<()> {
        if stream.codec().has_next() {
            Ok(())
        } else {
            match stream.next().await {
                None => Err(anyhow!("unexpected eof")),
                Some(res) => res,
            }
        }
    }

    async fn try_read_client_hello(&mut self, inbound: &mut TLSStream) -> Result<()> {
        self.read_from_stream(inbound)
            .await
            .context("failed to read client hello: ")?;
        let rtype = inbound.codec().peek_record_type()?;
        if rtype != RECORD_HANDSHAKE {
            return Err(anyhow!(
                "reject: incorrect record type for client hello, actual: {}",
                rtype
            ));
        }
        let record = inbound
            .codec_mut()
            .next_record()
            .expect("unexpected error: record has been checked");
        let mut cursor = Cursor::new(&*record);
        self.client_hello =
            Some(ClientHello::parse(&mut cursor).context("unable to parse client hello: ")?);
        Ok(())
    }

    async fn try_read_server_hello(&mut self, outbound: &mut TLSStream) -> Result<()> {
        self.read_from_stream(outbound)
            .await
            .context("failed to read server hello: ")?;
        let rtype = outbound.codec().peek_record_type()?;
        if rtype != RECORD_HANDSHAKE {
            return Err(anyhow!(
                "reject: incorrect record type for server hello, actual: {}",
                rtype
            ));
        }
        let record = outbound
            .codec_mut()
            .next_record()
            .expect("unexpected error: record has been checked");
        let mut cursor = Cursor::new(&*record);
        self.server_hello =
            Some(ServerHello::parse(&mut cursor).context("unable to parse client hello: ")?);
        Ok(())
    }

    async fn try_read_tls13_till_first_0x17(
        &mut self,
        outbound: &mut TLSStream,
        inbound: &mut TLSStream,
    ) -> Result<()> {
        let mut ccs_from_server = false;
        loop {
            self.read_from_stream(outbound).await?;
            let rtype = outbound.codec().peek_record_type()?;

            match rtype {
                RECORD_CCS if !ccs_from_server => {
                    ccs_from_server = true;
                }
                RECORD_APPLICATION_DATA if ccs_from_server => {
                    break;
                }
                _ => {
                    return Err(anyhow!(
                    "reject: incorrect outbound tls13 record type, expected 1 CCS or Application Data, actual {rtype}",
                ))
                }
            }
            outbound
                .codec_mut()
                .next_record()
                .expect("unexpected error: record has been checked");
            self.relay_to(inbound, outbound).await?;
        }

        Ok(())
    }

    fn prepare_server_auth(&self, outbound: &mut TLSStream) {
        let mut hasher = HmacSha1::new_from_slice(self.restls_password)
            .expect("sha1 should take key of any size");
        hasher.update(&self.server_hello.as_ref().unwrap().server_random);
        let secret = hasher.finalize().into_bytes();
        debug!(
            "server challenge {:?}",
            &secret[..RESTLS_HANDSHAKE_HMAC_LEN]
        );
        let record = outbound
            .codec_mut()
            .peek_record_mut()
            .expect("unexpected error: record has been checked");
        xor_bytes(&secret[..RESTLS_HANDSHAKE_HMAC_LEN], &mut record[5..]);
    }

    async fn try_read_tl13_till_client_application_data(
        &mut self,
        outbound: &mut TLSStream,
        inbound: &mut TLSStream,
    ) -> Result<()> {
        let mut seen_client_application_data = 0;
        let mut ccs_from_client = false;
        loop {
            select! {
                res = self.read_from_stream(inbound) => {
                    let _ = res?;
                    match inbound.codec().peek_record_type()? {
                        RECORD_CCS if !ccs_from_client => {
                            ccs_from_client = true;
                        }
                        RECORD_APPLICATION_DATA if ccs_from_client => {
                            seen_client_application_data += 1;
                            if seen_client_application_data == 2 {
                                break;
                            }
                        }
                        rtype => {
                            return Err(anyhow!(
                                "reject: incorrect inbound tls13 record type, expected 1 CCS or Application Data, actual {rtype}",
                            ));
                        }
                    }
                    inbound.codec_mut().next_record().expect("unexpected error: record has been checked");
                    self.relay_to(outbound, inbound).await?;
                }
                res = self.read_from_stream(outbound) => {
                    let _ = res?;
                    outbound.codec_mut().skip_to_end();
                    self.relay_to(inbound, outbound).await?;
                }
            }
        }
        Ok(())
    }

    fn check_tls13_session_id(&self) -> Result<()> {
        let mut hasher = HmacSha1::new_from_slice(self.restls_password)
            .expect("sha1 should take key of any size");
        let client_hello = self.client_hello.as_ref().unwrap();
        hasher.update(&client_hello.key_share);
        hasher.update(&client_hello.psk);
        let res_raw = hasher.finalize();
        let res = res_raw.into_bytes();
        let expect = &res[..RESTLS_HANDSHAKE_HMAC_LEN];
        let actual = &client_hello.session_id[..RESTLS_HANDSHAKE_HMAC_LEN];
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

    fn check_tls13_application_data_auth(&self, in_buf: &[u8]) -> Result<()> {
        let mut hasher = HmacSha1::new_from_slice(self.restls_password)
            .expect("sha1 should take key of any size");
        let server_hello = self.server_hello.as_ref().unwrap();
        hasher.update(&server_hello.server_random);
        hasher.update(&server_hello.server_random);
        let res = hasher.finalize().into_bytes();
        let expect = &res[..RESTLS_APPDATA_HMAC_LEN];
        let application_data = &in_buf[5..];
        if application_data.len() < RESTLS_APPDATA_HMAC_LEN {
            return Err(anyhow!(
                "reject: application data too short to contain an auth header"
            ));
        }
        let actual = &application_data[..RESTLS_APPDATA_HMAC_LEN];
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

    fn handle_tls12_outbound(&self, outbound: &mut TLSStream, flow: &mut TLS12Flow) -> Result<()> {
        let rtype = outbound.codec().peek_record_type()?;
        match rtype {
            RECORD_CCS => {
                flow.ccs_from_server()?;
            }
            RECORD_HANDSHAKE if flow.is_ccs_from_server() => {
                if flow.is_resume() {
                    self.check_tls12_session_ticket()?;
                }
                self.prepare_server_auth(outbound);
                debug!("sending tls12 server auth to client");
            }
            RECORD_HANDSHAKE => (),
            _ => {
                return Err(anyhow!(
                    "reject: incorrect outbound tls12 record type, expected 1 CCS or Handshake, actual {rtype}",
                ))
            }
        }
        Ok(())
    }

    fn handle_tls12_inbound(&mut self, inbound: &TLSStream, flow: &mut TLS12Flow) -> Result<()> {
        let rtype = inbound.codec().peek_record_type()?;
        match rtype {
            RECORD_CCS => {
                flow.ccs_from_client()?;
                Ok(())
            }
            RECORD_HANDSHAKE if flow.expect_cke() => {
                // We expect CKE to be the first 0x16 after client hello.
                let maybe_cke = inbound
                    .codec()
                    .peek_record()
                    .expect("unexpected error: record has been checked");
                ClientKeyExchange::check(
                    &mut Cursor::new(maybe_cke),
                    self.restls_password,
                    self.client_hello.as_ref().unwrap(),
                )?;
                flow.cke_verified()
            }
            RECORD_HANDSHAKE if flow.is_resume_ccs_from_client() => {
                // For tls 1.2 w/ resume, we need to hash the client finished.
                self.client_finished
                    .extend_from_slice(inbound.codec().peek_record().unwrap());

                Ok(())
            }
            RECORD_HANDSHAKE => Ok(()),
            RECORD_APPLICATION_DATA => flow.client_0x17(),
            _ => Err(anyhow!(
                "reject: incorrect tls12 inbound record type, expected 1 CCS or Handshake, actual {rtype}",
            )),
        }
    }

    async fn try_read_tls12_till_client_application_data(
        &mut self,
        outbound: &mut TLSStream,
        inbound: &mut TLSStream,
    ) -> Result<()> {
        let mut flow = TLS12Flow::Initial;
        loop {
            debug!("flow {:?}", flow);
            select! {
                ret = self.read_from_stream(outbound) => {
                    ret?;
                    self.handle_tls12_outbound(outbound, &mut flow)?;
                    outbound
                        .codec_mut()
                        .next_record()
                        .expect("unexpected error: record has been checked");
                    self.relay_to(inbound, outbound).await?;
                }
                ret = self.read_from_stream(inbound) => {
                    ret?;
                    self.handle_tls12_inbound(inbound, &mut flow)?;
                    if flow.is_client_0x17() {
                        break;
                    }
                    inbound
                        .codec_mut()
                        .next_record()
                        .expect("unexpected error: record has been checked");
                    self.relay_to(outbound, inbound).await?;
                }
            }
        }
        Ok(())
    }

    fn check_tls12_session_ticket(&self) -> Result<()> {
        let mut hasher = HmacSha1::new_from_slice(self.restls_password).expect("unexpected");
        let client_hello = self.client_hello.as_ref().unwrap();
        hasher.update(&client_hello.session_ticket);
        let actual_hash = hasher.finalize().into_bytes();
        if &client_hello.session_id[RESTLS_HANDSHAKE_HMAC_LEN..]
            != &actual_hash[..RESTLS_HANDSHAKE_HMAC_LEN]
        {
            Err(anyhow!("reject: tls 1.2 client pub key mismatched"))
        } else {
            Ok(())
        }
    }

    async fn relay_to(
        &mut self,
        to_stream: &mut TLSStream,
        from_stream: &mut TLSStream,
    ) -> Result<()> {
        if from_stream.codec().has_next() {
            return Ok(());
        }
        let res = match to_stream
            .get_mut()
            .write_all(&from_stream.codec().raw_buf())
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
        outbound: &mut TLSStream,
        inbound: &mut TLSStream,
    ) -> Result<()> {
        self.try_read_client_hello(inbound).await?;
        self.relay_to(outbound, inbound).await?;

        self.try_read_server_hello(outbound).await?;
        self.relay_to(inbound, outbound).await?;

        if self.server_hello.as_ref().unwrap().is_tls13 {
            self.check_tls13_session_id()?;
            self.try_read_tls13_till_first_0x17(outbound, inbound)
                .await?;
            self.prepare_server_auth(outbound);
            outbound.codec_mut().next_record().unwrap();
            debug!("sending tls13 server auth to client");
            self.relay_to(inbound, outbound).await?;
            self.try_read_tl13_till_client_application_data(outbound, inbound)
                .await?;
            self.check_tls13_application_data_auth(inbound.codec().peek_record()?)?;
        } else {
            self.try_read_tls12_till_client_application_data(outbound, inbound)
                .await?;
        }
        Ok(())
    }
}

pub async fn handle(options: Arc<Opt>, inbound: TcpStream) -> Result<()> {
    let mut outbound = TLSCodec::new_inbound().framed(
        // TcpStream::connect("89.145.65.200:443")
            TcpStream::connect(&options.server_hostname)
            .await
            .context("cannot connect to outbound".to_owned() + &options.server_hostname)?,
    );

    let mut inbound = TLSCodec::new_outbound().framed(inbound);
    let mut try_handshake = TryHandshake {
        client_hello: None,
        server_hello: None,
        restls_password: options.password.as_bytes(),
        client_finished: Vec::new(),
    };
    match try_handshake
        .try_handshake(&mut outbound, &mut inbound)
        .await
    {
        Ok(()) => {
            let outbound_proxy = TcpStream::connect(&options.forward_to).await?;
            copy_bidirectional(inbound, outbound_proxy).await?;
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
        tokio::spawn(async move {
            match handle(options, stream).await {
                Err(e) => tracing::debug!("{}", e),
                Ok(_) => (),
            }
        });
    }
}
