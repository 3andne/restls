use anyhow::{anyhow, Result};
use bytes::Buf;
use futures_util::StreamExt;
use rand::Rng;
use std::{
    cmp::min,
    io::{self, Cursor},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::TcpStream, select};
use tracing::debug;

use tokio_util::codec::{Decoder, Framed};

use crate::common::{BUF_SIZE, RECORD_HANDSHAKE};

pub type TLSStream = Framed<TcpStream, TLSCodec>;

#[derive(Debug)]
enum RecordChecker {
    Outbound,
    NewInbound,
    InboundAfterClientHello,
}

impl RecordChecker {
    fn check(&mut self, record: &[u8]) -> bool {
        use RecordChecker::*;
        match self {
            Outbound => true,
            NewInbound => {
                if &record[..3] == &[0x16, 0x03, 0x01] {
                    *self = InboundAfterClientHello;
                    true
                } else {
                    false
                }
            }
            InboundAfterClientHello => {
                record[0] >= 0x14 && record[0] <= 0x18 && &record[1..3] == &[0x03, 0x03]
            }
        }
    }
}

pub struct TLSCodec {
    checker: RecordChecker,
    buf: Vec<u8>,
    cursor: usize,
    pub enable_codec: bool,
}

impl TLSCodec {
    pub fn new_outbound() -> Self {
        Self {
            checker: RecordChecker::NewInbound,
            buf: Vec::with_capacity(0x2000),
            enable_codec: true,
            cursor: 0,
        }
    }

    pub fn new_inbound() -> Self {
        Self {
            checker: RecordChecker::Outbound,
            buf: Vec::with_capacity(0x2000),
            enable_codec: true,
            cursor: 0,
        }
    }

    pub fn reset(&mut self) {
        assert!(self.cursor == self.buf.len());
        unsafe {
            self.buf.set_len(0);
            self.cursor = 0;
        }
    }

    fn peek_record_length(&self) -> usize {
        5 + ((self.buf[self.cursor + 3] as usize) << 8 | self.buf[self.cursor + 4] as usize)
    }

    fn check_codec_failure(&self) -> Result<()> {
        if !self.enable_codec {
            Err(anyhow!("codec disabled due to invalid record"))
        } else {
            Ok(())
        }
    }

    pub fn next_record(&mut self) -> Result<&mut [u8]> {
        self.check_codec_failure()?;
        let start = self.cursor;
        self.cursor += self.peek_record_length();
        Ok(&mut self.buf[start..self.cursor])
    }

    pub fn peek_record(&self) -> Result<&[u8]> {
        self.check_codec_failure()?;
        let len = self.peek_record_length();
        Ok(&self.buf[self.cursor..self.cursor + len])
    }

    pub fn peek_record_mut(&mut self) -> Result<&mut [u8]> {
        self.check_codec_failure()?;
        let len = self.peek_record_length();
        Ok(&mut self.buf[self.cursor..self.cursor + len])
    }

    pub fn peek_record_type(&self) -> Result<u8> {
        self.check_codec_failure()?;
        Ok(self.buf[self.cursor])
    }

    pub fn has_next(&self) -> bool {
        self.cursor < self.buf.len()
    }

    pub fn skip_to_end(&mut self) {
        self.cursor = self.buf.len();
    }

    pub fn raw_buf(&self) -> &[u8] {
        assert!(self.cursor == self.buf.len());
        &self.buf
    }

    pub fn has_content(&self) -> bool {
        !self.buf.is_empty()
    }
}

impl Decoder for TLSCodec {
    type Item = ();

    type Error = anyhow::Error;

    fn decode(
        &mut self,
        src: &mut bytes::BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        self.reset();

        if !self.enable_codec {
            if src.len() == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&src);
            src.advance(src.len());
            return Ok(Some(()));
        }

        let mut cursor = 0;
        while cursor + 5 < src.len() {
            if !self.checker.check(&src[cursor..]) {
                debug!("record check failed: {:?}", &src[..]);
                self.enable_codec = false;
                return self.decode(src);
            }
            let record_len = ((src[cursor + 3] as u16) << 8 | (src[cursor + 4] as u16)) as usize;
            debug!("[{:?}]incoming record len: {}", self.checker, record_len);
            if src.len() < cursor + 5 + record_len {
                break;
            }
            cursor += 5 + record_len;
        }
        if cursor == 0 {
            return Ok(None);
        }
        self.buf.reserve(cursor);
        unsafe {
            self.buf.set_len(cursor);
        }

        src.copy_to_slice(&mut self.buf);

        tracing::debug!("[{:?}]decoded: {}", self.checker, self.buf.len());

        Ok(Some(()))
    }
}

pub(crate) fn read_length_padded_header<const N: usize, T: Buf>(buf: &mut T) -> Result<usize> {
    let mut len = 0;
    let mut tmp = [0; 8];
    if buf.remaining() < N {
        return Err(anyhow!(
            "read_length_padded_header failed: expect {}, actual {}",
            N,
            buf.remaining()
        ));
    }
    buf.copy_to_slice(&mut tmp[..N]);
    for i in 0..N {
        len = (len << 8) | (tmp[i] as usize);
    }
    Ok(len)
}

pub(crate) fn skip_length_padded<const N: usize, T: Buf>(buf: &mut T) -> Result<usize> {
    let len = read_length_padded_header::<N, T>(buf)?;
    buf.checked_advance(len, "skip_length_padded failed")?;
    Ok(len)
}

pub(crate) fn read_length_padded<const N: usize, T: Buf>(
    buf: &mut T,
    copy_to: &mut [u8],
) -> Result<usize> {
    let len = read_length_padded_header::<N, T>(buf)?;
    if copy_to.len() < len {
        return Err(anyhow!("truncated length padded content"));
    }
    buf.copy_to_slice(&mut copy_to[..len]);
    Ok(len)
}

pub(crate) fn extend_from_length_prefixed<const N: usize, T: Buf>(
    buf: &mut T,
    copy_to: &mut Vec<u8>,
) -> Result<()> {
    let len = read_length_padded_header::<N, T>(buf)?;
    if len > buf.remaining() {
        return Err(anyhow!(
            "extend_from_length_prefixed failed: expect {}, actual {}",
            len,
            buf.remaining()
        ));
    }
    copy_to.extend_from_slice(&buf.chunk()[..len]);
    buf.advance(len);
    Ok(())
}

pub(crate) fn length_prefixed<const N: usize, T: Buf, P: FnOnce(Cursor<&[u8]>) -> Result<()>>(
    buf: &mut T,
    parse: P,
) -> Result<()> {
    let len = read_length_padded_header::<N, _>(buf)?;
    if len > buf.remaining() {
        return Err(anyhow!(
            "read length_prefixed bytes failed: expect {}, actual {}",
            len,
            buf.remaining()
        ));
    }
    parse(Cursor::new(&buf.chunk()[..len]))?;
    buf.advance(len);
    Ok(())
}

pub(crate) fn u8_length_prefixed<T: Buf, P: FnOnce(Cursor<&[u8]>) -> Result<()>>(
    buf: &mut T,
    parse: P,
) -> Result<()> {
    length_prefixed::<1, _, _>(buf, parse)
}

pub(crate) fn u16_length_prefixed<T: Buf, P: FnOnce(Cursor<&[u8]>) -> Result<()>>(
    buf: &mut T,
    parse: P,
) -> Result<()> {
    length_prefixed::<2, _, _>(buf, parse)
}

pub(crate) fn xor_bytes(secret: &[u8], msg: &mut [u8]) {
    for i in 0..min(secret.len(), msg.len()) {
        msg[i] = msg[i] ^ secret[i];
    }
}

pub async fn tcp_rst(stream: &mut TcpStream) -> Result<()> {
    stream.set_linger(Some(Duration::from_secs(0)))?;
    stream.shutdown().await?;
    return Ok(());
}

pub async fn copy_bidirectional_fallback(
    mut inbound: TLSStream,
    mut outbound: TLSStream,
) -> Result<()> {
    inbound.codec_mut().enable_codec = false;
    outbound.codec_mut().enable_codec = false;
    if inbound.codec().has_content() {
        inbound.codec_mut().skip_to_end();
        debug!(
            "write old msg to inbound {}",
            inbound.codec().raw_buf().len()
        );
        outbound
            .get_mut()
            .write_all(inbound.codec().raw_buf())
            .await?;
    }
    if outbound.codec().has_content() {
        outbound.codec_mut().skip_to_end();
        debug!(
            "write old msg to outbound {}",
            outbound.codec().raw_buf().len()
        );
        inbound
            .get_mut()
            .write_all(outbound.codec().raw_buf())
            .await?;
    }

    debug!("start relaying");

    loop {
        select! {
            res = inbound.next() => {
                match res {
                    Some(Ok(_)) => (),
                    Some(Err(e)) => {
                        return Err(e);
                    }
                    None => {
                        return Err(anyhow!("inbound eof"));
                    }
                }
                inbound.codec_mut().skip_to_end();
                outbound.get_mut().write_all(inbound.codec().raw_buf()).await?;
            }
            res = outbound.next() => {
                match res {
                    Some(Ok(_)) => (),
                    Some(Err(root_cause)) => {
                        return match root_cause.downcast_ref::<io::Error>() {
                            Some(e) => {
                                match e.kind() {
                                    io::ErrorKind::ConnectionReset => {
                                        tcp_rst(inbound.get_mut()).await
                                    }
                                    _ => Err(root_cause),
                                }
                            },
                            None => Err(root_cause),
                        }
                    }
                    None => {
                        inbound.get_mut().write(&[]).await?;
                        return Ok(());
                    }
                }
                outbound.codec_mut().skip_to_end();
                inbound.get_mut().write_all(outbound.codec().raw_buf()).await?;
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RestlsCommand {
    Noop,
    Response(u8),
}

impl RestlsCommand {
    pub fn from_bytes(buf: &[u8]) -> Self {
        match buf[0] {
            0 => Self::Noop,
            1 => Self::Response(buf[1]),
            _ => unimplemented!("unsupported command type"),
        }
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        match self {
            Self::Noop => [0, 0],
            Self::Response(count) => [1, *count],
        }
    }
}

#[derive(Debug, Clone)]
struct TargetLen(u16, u16);

fn parse_int(cursor: &mut Cursor<&[u8]>) -> u16 {
    let mut res = 0;
    let len = cursor.chunk().len();
    let mut i = 0;
    while i < len {
        let b = cursor.chunk()[i];
        if b <= b'9' && b >= b'0' {
            res = res * 10 + (cursor.chunk()[i] - b'0') as u32;
        } else {
            break;
        }
        i += 1;
    }
    assert!(res < u16::MAX as u32);
    cursor.advance(i);
    res as u16
}

impl TargetLen {
    fn from_bytes(cursor: &mut Cursor<&[u8]>) -> Self {
        let base = parse_int(cursor);
        if !cursor.has_remaining() {
            return Self(base, 0);
        }
        match cursor.chunk()[0] {
            b'~' => {
                cursor.advance(1);
                Self(base, parse_int(cursor))
            }
            b'?' => {
                cursor.advance(1);
                let rng = parse_int(cursor);
                assert!((rng as u32) + (base as u32) < u16::MAX as u32);
                let new_base = base + rand::thread_rng().gen_range(0..rng);
                Self(new_base, 0)
            }
            _ => Self(base, 0),
        }
    }

    fn len(&self) -> usize {
        if self.1 == 0 {
            self.0 as usize
        } else {
            (self.0 + rand::thread_rng().gen_range(0..self.1)) as usize
        }
    }
}

#[derive(Debug, Clone)]
pub struct Line {
    target_len: TargetLen,
    pub command: RestlsCommand,
}

impl Line {
    pub fn len(&self) -> usize {
        self.target_len.len()
    }

    pub fn from_str(line_raw: &str) -> Self {
        let mut c = Cursor::new(line_raw.as_bytes());
        let target_len = TargetLen::from_bytes(&mut c);
        if !c.has_remaining() {
            return Self {
                target_len,
                command: RestlsCommand::Noop,
            };
        }
        match c.get_u8() {
            b'<' => {
                let response_count = parse_int(&mut c);
                assert!(
                    !c.has_remaining(),
                    "unexpected content in restls command {:?}",
                    String::from_utf8(c.chunk().to_vec()).unwrap()
                );
                assert!(
                    response_count < 255,
                    "too many response in restls script, expect < 255, actual {}",
                    response_count
                );
                return Self {
                    target_len,
                    command: RestlsCommand::Response(response_count as u8),
                };
            }
            _ => unimplemented!("unsupported command in restls script"),
        }
    }
}

pub struct DoubleCursorBuf {
    inner: [u8; BUF_SIZE],
    front_cursor: usize,
    back_cursor: usize,
    load_len: usize,
    conent_offset: usize,
}

impl DoubleCursorBuf {
    pub fn new(conent_offset: usize) -> Self {
        Self {
            inner: [0; BUF_SIZE],
            front_cursor: 0,
            back_cursor: conent_offset,
            load_len: 0,
            conent_offset,
        }
    }

    fn shift_to_head(&mut self) {
        if self.front_cursor == 0 {
            return;
        }
        unsafe {
            std::ptr::copy(
                self.inner[self.front_cursor..].as_ptr(),
                self.inner.as_mut_ptr(),
                self.back_cursor - self.front_cursor,
            );
        }
        self.back_cursor -= self.front_cursor;
        self.front_cursor = 0;
    }

    pub fn len(&self) -> usize {
        self.back_cursor - self.front_cursor - self.conent_offset
    }

    pub fn load_mut(&mut self) -> &mut [u8] {
        &mut self.inner[self.front_cursor..self.front_cursor + self.conent_offset + self.load_len]
    }

    pub fn release(&mut self) {
        self.front_cursor += self.load_len;
        self.load_len = 0;
        if self.front_cursor + self.conent_offset == self.back_cursor {
            self.reset()
        }
    }

    pub fn load(&mut self, len: usize) {
        assert!(self.load_len == 0);
        if len > self.len() {
            if self.inner.len() - self.front_cursor < 1500 {
                self.shift_to_head();
            }
            let padding_len = len - self.len();
            rand::thread_rng()
                .fill(&mut self.inner[self.back_cursor..self.back_cursor + padding_len]);
            self.back_cursor += padding_len;
            assert!(self.back_cursor < self.inner.len());
        }
        self.load_len = len;
    }

    pub fn reset(&mut self) {
        self.front_cursor = 0;
        self.back_cursor = self.conent_offset;
    }

    pub fn back_mut(&mut self) -> &mut [u8] {
        if self.inner.len() - self.back_cursor < 1500 {
            self.shift_to_head()
        }
        &mut self.inner[self.back_cursor..]
    }

    pub fn advance_back(&mut self, len: usize) {
        assert!(self.back_cursor + len <= self.inner.len());
        self.back_cursor += len;
    }
}

pub struct HandshakeRecord<'a> {
    hs_msg_cursor: usize,
    record: &'a mut [u8],
}

impl<'a> HandshakeRecord<'a> {
    pub fn new(record: &'a mut [u8]) -> Self {
        assert!(record[0] == RECORD_HANDSHAKE);
        Self {
            hs_msg_cursor: 5,
            record,
        }
    }

    fn peek_handshake_message_len(&self) -> Result<usize> {
        Ok(4 + ((self.record[self.hs_msg_cursor + 1] as usize) << 16
            | (self.record[self.hs_msg_cursor + 2] as usize) << 8
            | (self.record[self.hs_msg_cursor + 3] as usize)))
    }

    pub fn next_handshake_message(&mut self) -> Result<&mut [u8]> {
        let len = self.peek_handshake_message_len()?;
        let start = self.hs_msg_cursor;
        self.hs_msg_cursor += len;
        Ok(&mut self.record[start..self.hs_msg_cursor])
    }

    pub fn has_next(&self) -> bool {
        self.hs_msg_cursor < self.record.len()
    }
}

pub trait CheckedAdvance {
    fn checked_advance(&mut self, cnt: usize, err_msg: &str) -> Result<()>;
}

impl<T: Buf> CheckedAdvance for T {
    fn checked_advance(&mut self, cnt: usize, err_msg: &str) -> Result<()> {
        if cnt > self.remaining() {
            return Err(anyhow!(
                "{err_msg}, expect {}, actual {}",
                cnt,
                self.remaining()
            ));
        }
        self.advance(cnt);
        Ok(())
    }
}
