# (ROTP) Rust One Time Passwords

A simple HOTP and TOTP generator.

```
rotp 0.1.1
acheronfail <acheronfail@gmail.com>

USAGE:
    rotp <SUBCOMMAND>

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
rotp hotp --secret "$BASE32_SECRET" --counter 0    # 173468
rotp hotp --secret "$BASE32_SECRET" --counter 1    # 676177
rotp hotp --secret "$BASE32_SECRET" --counter 1729 # 102510

# TOTP
rotp totp --secret "$BASE32_SECRET" --time 30   --skew  0 # 173468
rotp totp --secret "$BASE32_SECRET" --time 3600 --skew  0 # 173468
rotp totp --secret "$BASE32_SECRET" --time 30   --skew  0 # 676177
rotp totp --secret "$BASE32_SECRET" --time 1    --skew -2 # 102510

# Alternatively, arguments may be passed via STDIN:
echo hotp --secret "$BASE32_SECRET" --counter 1729     | rotp # 102510
echo totp --secret "$BASE32_SECRET" --time 1 --skew -2 | rotp # 102510
```