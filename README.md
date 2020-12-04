# OTP

A simple HOTP and TOTP generator.

```
otp 0.1.0
acheronfail <acheronfail@gmail.com>

USAGE:
    otp <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help    Prints this message or the help of the given subcommand(s)
    hotp    Generate a HOTP code
    totp    Generate a TOTP code

```

## Examples

```bash
# Your OTP base32 encoded secret
export BASE32_SECRET="ALLYOURBASEAREBELONGTOUS"

# HOTP
otp hotp --secret "$BASE32_SECRET" --counter 0    # 173468
otp hotp --secret "$BASE32_SECRET" --counter 1    # 676177
otp hotp --secret "$BASE32_SECRET" --counter 1729 # 102510

# TOTP
otp totp --secret "$BASE32_SECRET" --time 30   --skew  0 # 173468
otp totp --secret "$BASE32_SECRET" --time 3600 --skew  0 # 173468
otp totp --secret "$BASE32_SECRET" --time 30   --skew  0 # 676177
otp totp --secret "$BASE32_SECRET" --time 1    --skew -2 # 102510

# Alternatively, arguments may be passed via STDIN:
echo hotp --secret "$BASE32_SECRET" --counter 1729     | otp # 102510
echo totp --secret "$BASE32_SECRET" --time 1 --skew -2 | otp # 102510
```