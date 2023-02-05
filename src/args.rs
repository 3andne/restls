use sha1::Digest;
use structopt::StructOpt;

fn parse_log_level(l: &str) -> tracing::Level {
    match &l.to_lowercase()[..] {
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        "trace" => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    }
}

fn parse_hostname(h: &str) -> String {
    if h.contains(":") {
        panic!("hostname should not contain ':', you shouldn't specify the port")
    }
    h.to_owned() + ":443"
}

#[derive(Debug, Clone)]
pub struct Password(Vec<u8>);

impl Password {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn make_password(h: &str) -> Password {
    let mut hasher = sha2::Sha512::new();
    hasher.update(h.as_bytes());
    let res = hasher.finalize();
    let mut res_vec = Vec::new();
    res_vec.extend_from_slice(res.as_slice());
    Password(res_vec)
}

#[derive(StructOpt, Clone, Debug)]
#[structopt(name = "basic")]
pub struct Opt {
    /// Log level (from least to most verbose):
    ///
    /// error < warn < info < debug < trace
    #[structopt(short = "o", long, default_value = "info", parse(from_str = parse_log_level))]
    pub log_level: tracing::Level,

    /// Server Name Indication (sni), or Hostname.
    #[structopt(short = "s", long, parse(from_str = parse_hostname))]
    pub server_hostname: String,

    /// server proxy port
    #[structopt(short = "l", long, default_value = "0.0.0.0:443")]
    pub listen: String,

    /// forward to an address on authentication finished
    #[structopt(short = "f", long)]
    pub forward_to: String,

    /// the password to authenticate connections
    #[structopt(short = "p", long, parse(from_str = make_password))]
    pub password: Password,
}

// #[derive(Debug)]
// pub struct RestlsContext {
//     pub options: Arc<Opt>,
//     pub shutdown: broadcast::Receiver<()>,
// }

// impl RestlsContext {
//     pub fn clone_with_signal(&self, shutdown: broadcast::Receiver<()>) -> Self {
//         Self {
//             options: self.options.clone(),
//             shutdown,
//         }
//     }
// }
