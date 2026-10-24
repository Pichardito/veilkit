//! Checksum validators. Each takes the matched text and answers "is this a
//! structurally valid X?". They are pure, allocation-light, and keyed by name
//! so a rule file can reference them without the engine knowing the rule.

/// Signature shared by every validator. Plain function pointers (not trait
/// objects) because validators carry no state.
pub type Validator = fn(&str) -> bool;

/// Look a validator up by the name used in rule files.
pub fn by_name(name: &str) -> Option<Validator> {
    Some(match name {
        "luhn" => luhn,
        "iban_mod97" => iban_mod97,
        "ssn" => ssn,
        "npi" => npi,
        "dea" => dea,
        "routing_aba" => routing_aba,
        _ => return None,
    })
}

/// Every validator name the engine knows, for docs and error messages.
pub const NAMES: &[&str] = &["luhn", "iban_mod97", "ssn", "npi", "dea", "routing_aba"];

fn digits(s: &str) -> Vec<u8> {
    s.bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect()
}

fn luhn_digits(d: &[u8]) -> bool {
    if d.len() < 2 {
        return false;
    }
    let mut sum = 0u32;
    for (i, &n) in d.iter().rev().enumerate() {
        let mut n = u32::from(n);
        if i % 2 == 1 {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
    }
    sum % 10 == 0
}

/// Luhn mod-10 over the digits of `s`, ignoring separators. Payment cards.
pub fn luhn(s: &str) -> bool {
    let d = digits(s);
    (12..=19).contains(&d.len()) && luhn_digits(&d)
}

/// ISO 13616 IBAN check: move the first four chars to the end, map letters
/// to 10..35, and the number must be 1 mod 97. Computed incrementally so it
/// never overflows.
pub fn iban_mod97(s: &str) -> bool {
    let cleaned: Vec<u8> = s
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if !(15..=34).contains(&cleaned.len()) {
        return false;
    }
    if !cleaned[0].is_ascii_alphabetic()
        || !cleaned[1].is_ascii_alphabetic()
        || !cleaned[2].is_ascii_digit()
        || !cleaned[3].is_ascii_digit()
    {
        return false;
    }
    let rotated = cleaned[4..].iter().chain(cleaned[..4].iter());
    let mut rem: u32 = 0;
    for &b in rotated {
        let v = if b.is_ascii_digit() {
            u32::from(b - b'0')
        } else {
            u32::from(b - b'A') + 10
        };
        // Letters contribute two digits; feed them one digit at a time.
        if v >= 10 {
            rem = (rem * 10 + v / 10) % 97;
            rem = (rem * 10 + v % 10) % 97;
        } else {
            rem = (rem * 10 + v) % 97;
        }
    }
    rem == 1
}

/// US Social Security Number structural rules: area not 000, 666 or 900-999;
/// group not 00; serial not 0000. Accepts 9 digits with or without separators.
pub fn ssn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    let area = u32::from(d[0]) * 100 + u32::from(d[1]) * 10 + u32::from(d[2]);
    let group = u32::from(d[3]) * 10 + u32::from(d[4]);
    let serial = d[5..].iter().fold(0u32, |a, &x| a * 10 + u32::from(x));
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// US National Provider Identifier: 10 digits, Luhn over the constant
/// prefix `80840` plus the identifier.
pub fn npi(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 {
        return false;
    }
    let mut full = vec![8, 0, 8, 4, 0];
    full.extend_from_slice(&d);
    luhn_digits(&full)
}

/// US DEA registration number: two letters then seven digits, where
/// (d1+d3+d5) + 2*(d2+d4+d6) ends in d7.
pub fn dea(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 9 || !b[0].is_ascii_alphabetic() || !(b[1].is_ascii_alphabetic() || b[1] == b'9')
    {
        return false;
    }
    let d: Vec<u32> = match b[2..]
        .iter()
        .map(|c| c.checked_sub(b'0'))
        .collect::<Option<Vec<u8>>>()
    {
        Some(v) if v.iter().all(|&x| x <= 9) => v.into_iter().map(u32::from).collect(),
        _ => return false,
    };
    let total = (d[0] + d[2] + d[4]) + 2 * (d[1] + d[3] + d[5]);
    total % 10 == d[6]
}

/// US ABA routing transit number: 9 digits with weights 3,7,1 summing to 0 mod 10.
pub fn routing_aba(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    const W: [u32; 9] = [3, 7, 1, 3, 7, 1, 3, 7, 1];
    let sum: u32 = d
        .iter()
        .zip(W.iter())
        .map(|(&x, &w)| u32::from(x) * w)
        .sum();
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_known_values() {
        assert!(luhn("4111 1111 1111 1111"));
        assert!(luhn("5500-0000-0000-0004"));
        assert!(luhn("378282246310005"));
        assert!(!luhn("4111 1111 1111 1112"));
        assert!(!luhn("1234"));
    }

    #[test]
    fn iban_known_values() {
        assert!(iban_mod97("GB82WEST12345698765432"));
        assert!(iban_mod97("DE89 3704 0044 0532 0130 00"));
        assert!(iban_mod97("FR7630006000011234567890189"));
        assert!(!iban_mod97("GB82WEST12345698765433"));
        assert!(!iban_mod97("1234WEST12345698765432"));
    }

    #[test]
    fn ssn_structure() {
        assert!(ssn("123-45-6789"));
        assert!(ssn("219099999"));
        assert!(!ssn("000-12-3456"));
        assert!(!ssn("666-12-3456"));
        assert!(!ssn("900-12-3456"));
        assert!(!ssn("123-00-4567"));
        assert!(!ssn("123-45-0000"));
        // Separator placement is the regex's job, not the validator's.
        assert!(ssn("12-345-6789"));
    }

    #[test]
    fn npi_check_digit() {
        assert!(npi("1234567893"));
        assert!(npi("1679576722"));
        assert!(!npi("1234567890"));
        assert!(!npi("123456789"));
    }

    #[test]
    fn dea_checksum() {
        assert!(dea("AB1234563"));
        assert!(dea("FG4567890"));
        assert!(dea("A91234563"));
        assert!(!dea("AB1234567"));
        assert!(!dea("A1234563"));
        assert!(!dea("ABX234563"));
    }

    #[test]
    fn aba_checksum() {
        assert!(routing_aba("021000021"));
        assert!(routing_aba("011000015"));
        assert!(routing_aba("121000248"));
        assert!(!routing_aba("021000022"));
        assert!(!routing_aba("02100002"));
    }

    #[test]
    fn lookup_by_name() {
        for n in NAMES {
            assert!(by_name(n).is_some(), "{n}");
        }
        assert!(by_name("nope").is_none());
    }
}
