mod cli;
mod otp;

use cli::{Args, Command};

fn main() {
    let args = Args::parse();
    let code = match args.command {
        Command::HOTP { secret, counter } => {
            otp::hotp(&secret, counter).expect("failed to generate HOTP code")
        }
        Command::TOTP {
            secret,
            time_step,
            skew,
        } => otp::totp(&secret, time_step, skew).expect("failed to generate TOTP code"),
    };

    println!("{}", code);
}
