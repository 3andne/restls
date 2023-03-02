use structopt::StructOpt;

use crate::utils::Line;

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
pub struct Script(Vec<Line>);

impl Script {
    pub fn get_line(&self, idx: usize) -> Option<&Line> {
        if idx < self.0.len() {
            Some(&self.0[idx])
        } else {
            None
        }
    }
}

fn parse_restls_script(script: &str) -> Script {
    Script(
        script
            .replace(" ", "")
            .split(",")
            .map(|l| Line::from_str(l))
            .collect::<Vec<_>>(),
    )
}

#[derive(Debug, Clone)]
pub struct Password([u8; 32]);

impl Password {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn make_password(h: &str) -> Password {
    let key = blake3::derive_key("restls-traffic-key", h.as_bytes());
    Password(key)
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

    /// A script used to guide how Restls sends and responds to application records. The complete syntax can be found at https://github.com/3andne/restls.   
    /// For example, the script "200?10,300~50,70<2,100~1000<1" specifies the behavior of the first four User Application Data Records for Restls: for the first data record, Restls will choose a random number between 200 and 210 at startup (let's say it's 203). The length of every first data packet for each connection will be 203. The length of the second packet will be a random number between 300 and 350. Unlike the first packet, its length will be different for each connection. The length of the third data packet is fixed at 70, and the peer (if we are the server, our peer is the client) is required to send two response records. The length of the fourth packet is between 100 and 1100, and the peer is required to send a response record.
    #[structopt(long, default_value = "200?100,200?100,1200?200<1,1100~300,1000~100<1,2500~500,1300~50,1300~50,100~1200", parse(from_str = parse_restls_script))]
    pub script: Script,

    /// The minimal length of server data. Packets that below this
    /// will be padded.
    #[structopt(long, default_value = "15")]
    pub min_record_len: u16,
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
