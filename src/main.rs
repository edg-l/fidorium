use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cfg = fidorium::config::Config::parse();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            if cfg.wipe {
                fidorium::wipe(cfg).await
            } else {
                fidorium::run(cfg).await
            }
        })
}
