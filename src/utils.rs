use anyhow::{anyhow, Result};
use bytes::Buf;
use futures_util::StreamExt;
use std::{cmp::min, io::Cursor};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    select,
};
use tracing::debug;

use tokio_util::codec::{Decoder, Framed};

use crate::common::RECORD_DUMMY;

pub type TLSStream = Framed<TcpStream, TLSCodec>;

pub struct TLSCodec {
    pub buf: Vec<u8>,
    pub need_header: bool,
    pub enable_codec: bool,
}

impl TLSCodec {
    pub fn new() -> Self {
        Self {
            need_header: true,
            buf: Vec::with_capacity(0x2000),
            enable_codec: true,
        }
    }

    pub fn reset(&mut self) {
        unsafe {
            self.buf.set_len(0);
        }
    }
}

impl Decoder for TLSCodec {
    type Item = u8;

    type Error = anyhow::Error;

    fn decode(
        &mut self,
        src: &mut bytes::BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        if !self.enable_codec {
            if src.len() == 0 {
                return Ok(None);
            }
            self.reset();
            self.buf.extend_from_slice(&src);
            src.advance(src.len());
            return Ok(Some(RECORD_DUMMY));
        }

        if src.len() < 5 {
            debug!("src len < 5");
            return Ok(None);
        }
        let rtype = src[0];
        let len = ((src[3] as u16) << 8 | (src[4] as u16)) as usize;
        debug!("incoming record len: {}", len);
        if src.len() < 5 + len {
            debug!("src.len() {} < 5 + len, {}", src.len(), 5 + len);
            src.reserve(5 + len - src.len());
            return Ok(None);
        }
        unsafe {
            self.buf.set_len(0);
            let buf_len = if self.need_header { len + 5 } else { len };
            self.buf.reserve(buf_len);
            self.buf.set_len(buf_len);
        }
        if !self.need_header {
            src.advance(5);
            src.copy_to_slice(&mut self.buf);
        } else {
            src.copy_to_slice(&mut self.buf);
        }

        tracing::debug!("decoded: {:?}", self.buf);

        Ok(Some(rtype))
    }
}

pub(crate) fn read_length_padded_header<const N: usize, T: Buf>(buf: &mut T) -> usize {
    let mut len = 0;
    let mut tmp = [0; 8];
    buf.copy_to_slice(&mut tmp[..N]);
    for i in 0..N {
        len = (len << 8) | (tmp[i] as usize);
    }
    len
}

pub(crate) fn skip_length_padded<const N: usize, T: Buf>(buf: &mut T) -> usize {
    let len = read_length_padded_header::<N, T>(buf);
    buf.advance(len);
    len
}

pub(crate) fn read_length_padded<const N: usize, T: Buf>(buf: &mut T, copy_to: &mut [u8]) -> usize {
    let len = read_length_padded_header::<N, T>(buf);
    assert!(copy_to.len() >= len);
    buf.copy_to_slice(&mut copy_to[..len]);
    len
}

pub(crate) fn extend_from_length_prefixed<const N: usize, T: Buf>(
    buf: &mut T,
    copy_to: &mut Vec<u8>,
) {
    let len = read_length_padded_header::<N, T>(buf);

    copy_to.extend_from_slice(&buf.chunk()[..len]);
    buf.advance(len);
}

pub(crate) fn length_prefixed<const N: usize, T: Buf, P: FnOnce(Cursor<&[u8]>)>(
    buf: &mut T,
    parse: P,
) {
    let len = read_length_padded_header::<N, _>(buf);
    parse(Cursor::new(&buf.chunk()[..len]));
    buf.advance(len);
}

pub(crate) fn u8_length_prefixed<T: Buf, P: FnOnce(Cursor<&[u8]>)>(buf: &mut T, parse: P) {
    length_prefixed::<1, _, _>(buf, parse);
}

pub(crate) fn u16_length_prefixed<T: Buf, P: FnOnce(Cursor<&[u8]>)>(buf: &mut T, parse: P) {
    length_prefixed::<2, _, _>(buf, parse);
}

pub(crate) fn xor_bytes(secret: &[u8], msg: &mut [u8]) {
    for i in 0..min(secret.len(), msg.len()) {
        msg[i] = msg[i] ^ secret[i];
    }
}

pub async fn copy_bidirectional(
    mut inbound: TLSStream,
    mut outbound: TcpStream,
    content_offset: usize,
) -> Result<()> {
    let mut out_buf = [0; 0x2000];
    out_buf[..3].copy_from_slice(&[0x17, 0x03, 0x03]);
    inbound.codec_mut().need_header = false;
    outbound
        .write_all(&inbound.codec().buf[content_offset..])
        .await?;
    inbound.codec_mut().reset();

    loop {
        select! {
            n = inbound.next() => {
                match n {
                    Some(Ok(v)) if v != 0 => (),
                    e => {
                        e.ok_or(anyhow!("relay inbound: "))??;
                    }
                }
                outbound.write_all(&inbound.codec().buf).await?;
                inbound.codec_mut().reset();
            }
            n = outbound.read(&mut out_buf[5..]) => {
                let n = n?;
                if n == 0 {
                    return Err(anyhow!("relay outbound: "));
                }
                out_buf[3..5].copy_from_slice(&(n as u16).to_be_bytes());
                inbound.get_mut().write_all(&out_buf[..n+5]).await?;
            }
        }
    }
}

pub async fn copy_bidirectional_fallback(
    mut inbound: TLSStream,
    mut outbound: TLSStream,
) -> Result<()> {
    inbound.codec_mut().enable_codec = false;
    outbound.codec_mut().enable_codec = false;
    if inbound.codec().buf.len() > 0 {
        debug!("write old msg to inbound {:?}", &inbound.codec().buf);
        outbound.get_mut().write_all(&inbound.codec().buf).await?;
    }
    if outbound.codec().buf.len() > 0 {
        debug!("write old msg to outbound {:?}", &outbound.codec().buf);
        inbound.get_mut().write_all(&outbound.codec().buf).await?;
    }

    debug!("start relaying");

    loop {
        select! {
            n = inbound.next() => {
                match n {
                    Some(Ok(v)) if v != 0 => (),
                    e => {
                        e.ok_or(anyhow!("relay inbound: "))??;
                    }
                }
                debug!("writing to outbound: {}", inbound.codec().buf.len());
                outbound.get_mut().write_all(&inbound.codec().buf).await?;
            }
            n = outbound.next() => {
                match n {
                    Some(Ok(v)) if v != 0 => (),
                    e => {
                        e.ok_or(anyhow!("relay inbound: "))??;
                    }
                }
                debug!("writing to inbound: {}", outbound.codec().buf.len());

                inbound.get_mut().write_all(&outbound.codec().buf).await?;
            }
        }
    }
}
