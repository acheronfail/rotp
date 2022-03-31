mod cli;
mod otp;

use cli::{Args, Command};

fn main() {
    let args = Args::parse();
    let code = match args.command {
        Command::HOTP {
            secret,
            counter,
            algorithm,
        } => otp::hotp(&secret.to_uppercase(), counter, algorithm),
        Command::TOTP {
            secret,
            time_step,
            skew,
            algorithm,
        } => otp::totp(&secret.to_uppercase(), time_step, skew, algorithm),
    };

    match code {
        Ok(code) => println!("{:06}", code),
        Err(e) => eprintln!("Failed to generate code: {}", e),
    }
}
