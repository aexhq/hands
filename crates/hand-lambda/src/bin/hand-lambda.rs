//! Narrow operator CLI for immutable image publication and explicit lifecycle inspection.

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use hand_lambda::REGION;
use hand_lambda::canary::{
    NetworkBoundaryCanaryConfig, NoRespawnCanaryConfig, run_network_boundary_canary,
    run_no_respawn_canary,
};
use hand_lambda::control::Control;
use hand_lambda::image::{self, PublishConfig};

#[derive(Parser)]
#[command(name = "hand-lambda", about = "Aex Hand Lambda MicroVM operator")]
struct Cli {
    #[arg(long, default_value = REGION)]
    region: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    List,
    Get {
        id: String,
    },
    Suspend {
        id: String,
    },
    Resume {
        id: String,
    },
    Terminate {
        id: String,
    },
}

#[derive(Subcommand)]
enum ImageCommand {
    Publish {
        #[arg(long)]
        binary: std::path::PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        bucket: String,
        #[arg(long)]
        build_role: String,
        #[arg(long)]
        log_group: String,
        #[arg(long = "egress-connector", required = true)]
        egress_connectors: Vec<String>,
    },
    Status {
        name: String,
    },
    Dockerfile,
    /// Destructive dev release gate: launches and always terminates one exact image version.
    Canary {
        #[arg(long)]
        image_arn: String,
        #[arg(long)]
        image_version: String,
        #[arg(long)]
        none_connector: String,
        #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
        confirm_dev_image_canary: bool,
    },
    /// Destructive dev release gate: proves all three connector classes on the exact image.
    NetworkCanary {
        #[arg(long)]
        image_arn: String,
        #[arg(long)]
        image_version: String,
        #[arg(long)]
        none_connector: String,
        #[arg(long)]
        allowlist_connector: String,
        #[arg(long)]
        public_connector: String,
        #[arg(long)]
        gateway_authority: String,
        /// Host-only API Gateway names from the dev and production Platform outputs.
        #[arg(long = "customer-hand-host", required = true, action = clap::ArgAction::Append)]
        customer_hand_hosts: Vec<String>,
        #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
        confirm_dev_network_canary: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hand_lambda=info".parse()?),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let control = Control::from_env(&cli.region).await?;
    match cli.command {
        Command::Image { command } => image_command(&control, &cli.region, command).await,
        Command::List => {
            for vm in control.list().await? {
                println!("{}\t{:?}", vm.id, vm.state);
            }
            Ok(())
        }
        Command::Get { id } => {
            let vm = control.get(&id).await?;
            println!(
                "{}\t{:?}\t{}",
                vm.id,
                vm.state,
                vm.endpoint.unwrap_or_default()
            );
            Ok(())
        }
        Command::Suspend { id } => control.suspend(&id).await.map_err(Into::into),
        Command::Resume { id } => control.resume(&id).await.map_err(Into::into),
        Command::Terminate { id } => control.terminate(&id).await.map_err(Into::into),
    }
}

async fn image_command(
    control: &Control,
    region: &str,
    command: ImageCommand,
) -> anyhow::Result<()> {
    match command {
        ImageCommand::Dockerfile => {
            print!("{}", image::dockerfile());
            Ok(())
        }
        ImageCommand::Canary {
            image_arn,
            image_version,
            none_connector,
            confirm_dev_image_canary,
        } => {
            anyhow::ensure!(
                confirm_dev_image_canary,
                "--confirm-dev-image-canary is required"
            );
            let http = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?;
            run_no_respawn_canary(
                control,
                &http,
                NoRespawnCanaryConfig {
                    image_arn,
                    image_version,
                    none_connector: hand_core::connector::ConnectorRef::parse(none_connector)?,
                },
            )
            .await
        }
        ImageCommand::NetworkCanary {
            image_arn,
            image_version,
            none_connector,
            allowlist_connector,
            public_connector,
            gateway_authority,
            customer_hand_hosts,
            confirm_dev_network_canary,
        } => {
            anyhow::ensure!(
                confirm_dev_network_canary,
                "--confirm-dev-network-canary is required"
            );
            let customer_hand_hosts: [String; 2] =
                customer_hand_hosts.try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "exactly two --customer-hand-host values are required (dev and production)"
                    )
                })?;
            run_network_boundary_canary(
                control,
                NetworkBoundaryCanaryConfig {
                    image_arn,
                    image_version,
                    none_connector: hand_core::connector::ConnectorRef::parse(none_connector)?,
                    allowlist_connector: hand_core::connector::ConnectorRef::parse(
                        allowlist_connector,
                    )?,
                    public_connector: hand_core::connector::ConnectorRef::parse(public_connector)?,
                    gateway_authority: hand_core::connector::GatewayAuthority::parse(
                        &gateway_authority,
                    )?,
                    customer_hand_hosts,
                },
            )
            .await
        }
        ImageCommand::Publish {
            binary,
            name,
            bucket,
            build_role,
            log_group,
            egress_connectors,
        } => {
            let bytes =
                std::fs::read(&binary).with_context(|| format!("reading {}", binary.display()))?;
            anyhow::ensure!(
                bytes.len() > 19 && bytes[..4] == [0x7f, b'E', b'L', b'F'] && bytes[18] == 0xb7,
                "{} is not an aarch64 ELF binary",
                binary.display()
            );
            let zip = image::pack_zip(&bytes)?;
            let aws = aws_config::from_env()
                .region(aws_config::Region::new(region.to_owned()))
                .load()
                .await;
            let s3 = aws_sdk_s3::Client::new(&aws);
            let published = image::publish(
                control,
                &s3,
                &PublishConfig {
                    name,
                    bucket,
                    build_role_arn: build_role,
                    log_group,
                    egress_connectors,
                },
                zip,
            )
            .await?;
            println!("{}\t{}", published.image_arn, published.image_version);
            Ok(())
        }
        ImageCommand::Status { name } => {
            let Some(arn) = image::find_image_arn(control, &name).await? else {
                bail!("no image named {name}");
            };
            let versions = control
                .sdk()
                .list_microvm_image_versions()
                .image_identifier(&arn)
                .send()
                .await?;
            for version in versions.items() {
                println!(
                    "{}\t{:?}\t{:?}\tbase={}",
                    version.image_version(),
                    version.state(),
                    version.status(),
                    version.base_image_version().unwrap_or("?")
                );
            }
            Ok(())
        }
    }
}
