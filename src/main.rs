use args::Opt;

use structopt::StructOpt;
mod args;
mod client_hello;
mod common;
mod restls;
mod server_hello;
mod utils;
mod client_key_exchange;

use std::{io::Result, sync::Arc};

#[tokio::main]
async fn main() -> Result<()> {
    let options = Opt::from_args();
    let collector = tracing_subscriber::fmt()
        .with_max_level(options.log_level)
        .with_target(if cfg!(feature = "debug_info") {
            true
        } else {
            false
        })
        .finish();
    let _ = tracing::subscriber::set_global_default(collector);

    if let Err(e) = restls::start(Arc::new(options)).await {
        tracing::error!("failed to start Restls server: {:?}", e);
    }
    Ok(())
}
