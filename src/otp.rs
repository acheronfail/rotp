use std::convert::TryInto;
use std::time::SystemTime;

use anyhow::{bail, Result};
use data_encoding::BASE32_NOPAD;
use ring::hmac;

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
pub fn hotp(secret: &str, counter: u64) -> Result<u32> {
    let decoded = BASE32_NOPAD.decode(secret.as_bytes())?;
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &decoded);
    let digest = hmac::sign(&key, &counter.to_be_bytes());
    encode_digest(digest.as_ref())
}

/// Helper function for `totp` to make it testable. Note that times
/// before Unix epoch are not supported.
fn make_totp(secret: &str, time_step: u64, skew: i64, time: u64) -> Result<u32> {
    let counter = ((time as i64 + skew) as u64) / time_step;
    hotp(secret, counter)
}

/// Performs the [Time-based One-time Password Algorithm](http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
/// `secret`: is an RFC4648 base32 encoded secret
/// `time_step`: is the time step in seconds
/// `skew`: is the skew in seconds
pub fn totp(secret: &str, time_step: u64, skew: i64) -> Result<u32> {
    let now = SystemTime::now();
    let time_since_epoch = now.duration_since(SystemTime::UNIX_EPOCH)?;
    Ok(make_totp(
        secret,
        time_step,
        skew,
        time_since_epoch.as_secs(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::{hotp, make_totp};

    const BASE32_SECRET: &str = "ALLYOURBASEAREBELONGTOUS";

    #[test]
    fn test_hotp() {
        assert_eq!(hotp(BASE32_SECRET, 0).unwrap(), 173468);
        assert_eq!(hotp(BASE32_SECRET, 1).unwrap(), 676177);
        assert_eq!(hotp(BASE32_SECRET, 1401).unwrap(), 118134);
    }

    #[test]
    fn test_totp() {
        assert_eq!(make_totp(BASE32_SECRET, 30, 0, 0).unwrap(), 173468);
        assert_eq!(make_totp(BASE32_SECRET, 3600, 0, 7).unwrap(), 173468);
        assert_eq!(make_totp(BASE32_SECRET, 30, 0, 35).unwrap(), 676177);
        assert_eq!(make_totp(BASE32_SECRET, 1, -2, 1403).unwrap(), 118134);
    }
}
