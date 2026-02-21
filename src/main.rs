use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cfg = fidorium::config::Config::parse();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(fidorium::run(cfg))
}
