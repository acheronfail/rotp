use std::convert::TryInto;
use std::time::SystemTime;

use anyhow::{bail, Result};
use data_encoding::BASE32_NOPAD;
use ring::hmac;

use crate::cli::Algorithm;

/// Encodes the HMAC digest into a 6-digit integer.
fn encode_digest(digest: &[u8]) -> Result<u32> {
    let offset = match digest.last() {
        Some(x) => (*x & 0xf) as usize,
        None => bail!("InvalidDigest: {:?}", Vec::from(digest)),
    };

    let code_bytes: [u8; 4] = match digest[offset..offset + 4].try_into() {
        Ok(x) => x,
        Err(_) => bail!("InvalidDigest: {:?}", Vec::from(digest)),
    };

    let code = u32::from_be_bytes(code_bytes);
    Ok((code & 0x7fffffff) % 1_000_000)
}

/// Performs the [HMAC-based One-time Password Algorithm](http://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm)
/// `secret`: is an RFC4648 base32 encoded secret
/// `counter`: is the integer counter
pub fn hotp(secret: &str, counter: u64, alg: Algorithm) -> Result<u32> {
    let alg = match alg {
        Algorithm::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        Algorithm::Sha256 => hmac::HMAC_SHA256,
        Algorithm::Sha512 => hmac::HMAC_SHA512,
    };

    let decoded = BASE32_NOPAD.decode(secret.as_bytes())?;
    let key = hmac::Key::new(alg, &decoded);
    let digest = hmac::sign(&key, &counter.to_be_bytes());
    encode_digest(digest.as_ref())
}

/// Helper function for `totp` to make it testable.
fn make_totp(secret: &str, time_step: u64, skew: i64, time: u64, alg: Algorithm) -> Result<u32> {
    if time_step == 0 {
        bail!("time-step must be > 0");
    }

    let time_with_skew = time as i64 + skew;
    if time_with_skew < 0 {
        bail!("time + skew must be >= 0");
    }

    let counter = (time_with_skew as u64) / time_step;
    hotp(secret, counter, alg)
}

/// Performs the [Time-based One-time Password Algorithm](http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
/// `secret`: is an RFC4648 base32 encoded secret
/// `time_step`: is the time step in seconds
/// `skew`: is the skew in seconds
pub fn totp(secret: &str, time_step: u64, skew: i64, alg: Algorithm) -> Result<u32> {
    let now = SystemTime::now();
    let time_since_epoch = now.duration_since(SystemTime::UNIX_EPOCH)?;
    Ok(make_totp(
        secret,
        time_step,
        skew,
        time_since_epoch.as_secs(),
        alg,
    )?)
}

#[cfg(test)]
mod tests {
    use super::{hotp, make_totp};
    use crate::cli::Algorithm;

    const BASE32_SECRET: &str = "ALLYOURBASEAREBELONGTOUS";

    #[test]
    fn hotp_works() {
        assert_eq!(hotp(BASE32_SECRET, 0, Algorithm::Sha1).unwrap(), 173468);
        assert_eq!(hotp(BASE32_SECRET, 1, Algorithm::Sha1).unwrap(), 676177);
        assert_eq!(hotp(BASE32_SECRET, 1729, Algorithm::Sha1).unwrap(), 102510);
    }

    #[test]
    fn hotp_256_works() {
        assert_eq!(hotp(BASE32_SECRET, 0, Algorithm::Sha256).unwrap(), 956455);
        assert_eq!(hotp(BASE32_SECRET, 1, Algorithm::Sha256).unwrap(), 401157);
        assert_eq!(
            hotp(BASE32_SECRET, 1729, Algorithm::Sha256).unwrap(),
            205436
        );
    }

    #[test]
    fn hotp_512_works() {
        assert_eq!(hotp(BASE32_SECRET, 0, Algorithm::Sha512).unwrap(), 281533);
        assert_eq!(hotp(BASE32_SECRET, 1, Algorithm::Sha512).unwrap(), 656777);
        assert_eq!(
            hotp(BASE32_SECRET, 1729, Algorithm::Sha512).unwrap(),
            924744
        );
    }

    #[test]
    fn totp_works() {
        assert_eq!(
            make_totp(BASE32_SECRET, 30, 0, 0, Algorithm::Sha1).unwrap(),
            173468
        );
        assert_eq!(
            make_totp(BASE32_SECRET, 3600, 0, 7, Algorithm::Sha1).unwrap(),
            173468
        );
        assert_eq!(
            make_totp(BASE32_SECRET, 30, 0, 35, Algorithm::Sha1).unwrap(),
            676177
        );
        assert_eq!(
            make_totp(BASE32_SECRET, 1, -2, 1731, Algorithm::Sha1).unwrap(),
            102510
        );
    }

    #[test]
    fn totp_256_works() {
        assert_eq!(
            make_totp(BASE32_SECRET, 30, 0, 0, Algorithm::Sha256).unwrap(),
            956455
        );
        assert_eq!(
            make_totp(BASE32_SECRET, 3600, 0, 7, Algorithm::Sha256).unwrap(),
            956455
        );
        assert_eq!(
            make_totp(BASE32_SECRET, 30, 0, 35, Algorithm::Sha256).unwrap(),
            401157
        );
        assert_eq!(
            make_totp(BASE32_SECRET, 1, -2, 1731, Algorithm::Sha256).unwrap(),
            205436
        );
    }

    #[test]
    fn totp_512_works() {
        assert_eq!(
            make_totp(BASE32_SECRET, 30, 0, 0, Algorithm::Sha512).unwrap(),
            281533
        );
        assert_eq!(
            make_totp(BASE32_SECRET, 3600, 0, 7, Algorithm::Sha512).unwrap(),
            281533
        );
        assert_eq!(
            make_totp(BASE32_SECRET, 30, 0, 35, Algorithm::Sha512).unwrap(),
            656777
        );
        assert_eq!(
            make_totp(BASE32_SECRET, 1, -2, 1731, Algorithm::Sha512).unwrap(),
            924744
        );
    }

    #[test]
    fn totp_time_step_gt_zero() {
        assert_eq!(
            format!(
                "{}",
                make_totp(BASE32_SECRET, 0, 0, 0, Algorithm::Sha1).unwrap_err()
            ),
            "time-step must be > 0"
        );
    }

    #[test]
    fn totp_time_and_skew_ge_zero() {
        assert_eq!(
            format!(
                "{}",
                make_totp(BASE32_SECRET, 30, -10, 5, Algorithm::Sha1).unwrap_err()
            ),
            "time + skew must be >= 0"
        );
    }
}
