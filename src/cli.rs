use clap::{Clap, crate_version, crate_authors};
use clap::AppSettings::ColoredHelp;

#[derive(Clap)]
#[clap(version = crate_version!(), author = crate_authors!(), global_setting(ColoredHelp))]
pub struct Args {
    #[clap(subcommand)]
    pub command: Command
}

impl Args {
    pub fn parse() -> Args {
        <Args as Clap>::parse()
    }
}

#[derive(Clap)]
pub enum Command {
    /// Generate a HOTP code
    HOTP {
        /// HOTP secret encoded in base32 (without padding)
        #[clap(short = 's', long = "secret")]
        secret: String,
        /// The counter for the HOTP
        #[clap(short = 'c', long = "counter")]
        counter: u64,
    },
    /// Generate a TOTP code
    TOTP {
        /// TOTP secret encoded in base32 (without padding)
        #[clap(short = 's', long = "secret")]
        secret: String,
        /// Time step in seconds
        #[clap(short = 't', long = "time")]
        time_step: u64,
        /// Skew in seconds
        #[clap(short = 'k', long = "skew")]
        skew: i64
    },
}
