mod cli;
mod otp;

use cli::{Args, Command};

fn main() {
    let args = Args::parse();
    let code = match args.command {
        Command::HOTP { secret, counter } => {
            otp::hotp(&secret, counter)
        }
        Command::TOTP {
            secret,
            time_step,
            skew,
        } => otp::totp(&secret, time_step, skew),
    };

    match code {
        Ok(code) => println!("{}", code),
        Err(e) => eprintln!("Failed to generate code: {}", e)
    }
}
