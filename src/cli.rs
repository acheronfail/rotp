use std::io::{self, Read};
use std::str::FromStr;

use atty::Stream;
use clap::ArgSettings::AllowHyphenValues;
use clap::{crate_authors, crate_name, crate_version, Parser};

/// All arguments may also be passed via STDIN, eg: echo "hotp --secret X --counter Y | otp"
#[derive(Parser)]
#[clap(version = crate_version!(), author = crate_authors!())]
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

            <Args as Parser>::parse_from(
                format!("{} {}", crate_name!(), stdin_args).split_ascii_whitespace(),
            )
        } else {
            <Args as Parser>::parse()
        }
    }
}

#[derive(Debug, Parser)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl FromStr for Algorithm {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => Err(format!(
                "Algorithm must be 'sha1', 'sha256' or 'sha512'. Got '{}'.",
                s
            )),
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::Sha1
    }
}

#[derive(Debug, Parser)]
pub enum Command {
    /// Generate a HOTP code
    HOTP {
        /// HOTP secret encoded in base32 (without padding)
        #[clap(short = 's', long = "secret")]
        secret: String,
        /// The counter for the HOTP
        #[clap(short = 'c', long = "counter")]
        counter: u64,
        /// Which algorithm to use
        #[clap(short = 'a', long = "algorithm", default_value = "sha1")]
        algorithm: Algorithm,
    },
    /// Generate a TOTP code
    TOTP {
        /// TOTP secret encoded in base32 (without padding)
        #[clap(short = 's', long = "secret")]
        secret: String,
        /// Time step in seconds. Defaults to 30.
        #[clap(short = 't', long = "time", default_value = "30")]
        time_step: u64,
        /// Skew in seconds
        #[clap(short = 'k', long = "skew", setting(AllowHyphenValues))]
        skew: i64,
        /// Which algorithm to use
        #[clap(short = 'a', long = "algorithm", default_value = "sha1")]
        algorithm: Algorithm,
    },
}
