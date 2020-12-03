use std::io::{self, Read};

use atty::Stream;
use clap::AppSettings::ColoredHelp;
use clap::ArgSettings::AllowHyphenValues;
use clap::{crate_authors, crate_name, crate_version, Clap};

/// All arguments may also be passed via STDIN, eg: echo "hotp --secret X --counter Y | otp"
#[derive(Clap)]
#[clap(version = crate_version!(), author = crate_authors!(), global_setting(ColoredHelp))]
pub struct Args {
    #[clap(subcommand)]
    pub command: Command,
}

impl Args {
    pub fn parse() -> Args {
        // If there's data on STDIN, then parse arguments from there
        if !atty::is(Stream::Stdin) {
            let stdin = io::stdin();
            let mut stdin_args = String::new();
            stdin
                .lock()
                .read_to_string(&mut stdin_args)
                .expect("failed to read arguments from STDIN");

            <Args as Clap>::parse_from(
                format!("{} {}", crate_name!(), stdin_args).split_ascii_whitespace(),
            )
        } else {
            <Args as Clap>::parse()
        }
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
        #[clap(setting(AllowHyphenValues))]
        skew: i64,
    },
}
