// protocol constants
pub const REQUIRED_SESSION_ID_LEN: usize = 32;
pub const REQUIRED_HMAC_LEN: usize = 16;

// record type
pub const RECORD_HANDSHAKE: u8 = 0x16;
pub const RECORD_APPLICATION_DATA: u8 = 0x17;
pub const RECORD_CCS: u8 = 0x14;
pub const RECORD_ALERT: u8 = 0x15;

// extension type
pub const EXTENSION_SESSION_TICKET: u16 = 0x0023;
pub const EXTENSION_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const EXTENSION_PRE_SHARED_KEY: u16 = 0x0029;
pub const EXTENSION_KEY_SHARE: u16 = 0x0033;

// handshake type:
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 01;
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 02;

pub const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];
