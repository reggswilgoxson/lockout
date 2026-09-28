//! Check-digit and format validators. Each takes the identifier with
//! separators already removed and returns whether it is structurally valid.

/// Luhn check (payment cards).
pub fn luhn(digits: &str) -> bool {
    let mut sum = 0;
    for (i, b) in digits.bytes().rev().enumerate() {
        let mut d = (b - b'0') as u32;
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum % 10 == 0
}

/// Card number: 13–19 digits, known issuer prefix, Luhn.
pub fn card(digits: &str) -> bool {
    let n = digits.len();
    let p = |len: usize| digits[..len].parse::<u32>().unwrap_or(0);
    let issuer = match digits.as_bytes()[0] {
        b'4' => matches!(n, 13 | 16 | 19),                // Visa
        b'5' => (51..=55).contains(&p(2)) && n == 16,     // Mastercard
        b'2' => (2221..=2720).contains(&p(4)) && n == 16, // Mastercard 2-series
        b'3' => {
            (matches!(p(2), 34 | 37) && n == 15)                                         // Amex
                || ((3528..=3589).contains(&p(4)) && (16..=19).contains(&n))             // JCB
                || ((matches!(p(2), 36 | 38 | 39) || (300..=305).contains(&p(3))) && (14..=19).contains(&n)) // Diners
        }
        b'6' => {
            (p(4) == 6011 || p(2) == 65 || (644..=649).contains(&p(3)) || p(2) == 62) && (16..=19).contains(&n) // Discover, UnionPay
        }
        _ => false,
    };
    issuer && luhn(digits)
}

/// Expected IBAN length for a country code.
pub fn iban_length(country: &str) -> Option<usize> {
    Some(match country {
        "NO" => 15,
        "BE" => 16,
        "DK" | "FI" | "FO" | "GL" | "NL" => 18,
        "MK" | "SI" => 19,
        "AT" | "BA" | "EE" | "KZ" | "LT" | "LU" | "XK" => 20,
        "CH" | "HR" | "LI" | "LV" => 21,
        "BG" | "BH" | "CR" | "DE" | "GB" | "GE" | "IE" | "ME" | "RS" | "VA" => 22,
        "AE" | "GI" | "IL" | "IQ" | "TL" => 23,
        "AD" | "CZ" | "ES" | "MD" | "PK" | "RO" | "SA" | "SE" | "SK" | "TN" | "VG" => 24,
        "PT" | "ST" => 25,
        "IS" | "TR" => 26,
        "FR" | "GR" | "IT" | "MC" | "MR" | "SM" => 27,
        "AL" | "AZ" | "BY" | "CY" | "DO" | "GT" | "HU" | "LB" | "PL" | "SV" => 28,
        "BR" | "EG" | "PS" | "QA" | "UA" => 29,
        "JO" | "KW" | "MU" => 30,
        "MT" | "SC" => 31,
        "LC" => 32,
        _ => return None,
    })
}

/// IBAN mod-97 (ISO 13616). Input is uppercase alphanumerics of the right length.
pub fn iban(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 5 || !b[2].is_ascii_digit() || !b[3].is_ascii_digit() {
        return false;
    }
    let mut rem: u32 = 0;
    for &c in b[4..].iter().chain(&b[..4]) {
        let v = match c {
            b'0'..=b'9' => (c - b'0') as u32,
            b'A'..=b'Z' => (c - b'A') as u32 + 10,
            _ => return false,
        };
        rem = if v >= 10 { (rem * 100 + v) % 97 } else { (rem * 10 + v) % 97 };
    }
    rem == 1
}

/// US Social Security number, 9 digits: area/group/serial rules.
pub fn us_ssn(d: &str) -> bool {
    let area: u32 = d[..3].parse().unwrap_or(0);
    let group: u32 = d[3..5].parse().unwrap_or(0);
    let serial: u32 = d[5..].parse().unwrap_or(0);
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// UK National Insurance number, 9 chars (prefix rules; the regex handles letters).
pub fn uk_nino(s: &str) -> bool {
    !matches!(&s[..2], "BG" | "GB" | "NK" | "KN" | "TN" | "NT" | "ZZ")
}

/// German tax ID (Steuerliche Identifikationsnummer), 11 digits, ISO 7064 MOD 11,10
/// plus the digit-distribution rule for the first ten digits.
pub fn de_steuer_id(d: &str) -> bool {
    let b = d.as_bytes();
    if b.len() != 11 || b[0] == b'0' {
        return false;
    }
    let mut counts = [0u8; 10];
    for &c in &b[..10] {
        counts[(c - b'0') as usize] += 1;
    }
    let repeated: Vec<u8> = counts.iter().copied().filter(|&n| n > 1).collect();
    if repeated.len() != 1 || repeated[0] > 3 {
        return false;
    }
    let mut product = 10;
    for &c in &b[..10] {
        let mut sum = ((c - b'0') as u32 + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    let check = (11 - product) % 10;
    check == (b[10] - b'0') as u32
}

/// French social security number (NIR), 15 chars; Corsica departments 2A/2B allowed.
pub fn fr_nir(s: &str) -> bool {
    let body = &s[..13];
    let key: u64 = match s[13..].parse() {
        Ok(k) => k,
        Err(_) => return false,
    };
    let numeric = body.replace("2A", "19").replace("2B", "18");
    let n: u64 = match numeric.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let n = if body[5..7] == *"2A" {
        n - 1_000_000
    } else if body[5..7] == *"2B" {
        n - 2_000_000
    } else {
        n
    };
    97 - n % 97 == key
}

const DNI_LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// Spanish DNI (8 digits + letter) or NIE (X/Y/Z + 7 digits + letter).
pub fn es_dni_nie(s: &str) -> bool {
    let b = s.as_bytes();
    let (lead, rest) = match b[0] {
        b'X' => ("0", &s[1..]),
        b'Y' => ("1", &s[1..]),
        b'Z' => ("2", &s[1..]),
        _ => ("", s),
    };
    let digits = format!("{lead}{}", &rest[..rest.len() - 1]);
    match digits.parse::<u32>() {
        Ok(n) if digits.len() == 8 => DNI_LETTERS[(n % 23) as usize] == *b.last().unwrap(),
        _ => false,
    }
}

/// Italian codice fiscale, 16 chars, check character.
pub fn it_codice_fiscale(s: &str) -> bool {
    const ODD: [u32; 26] =
        [1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23];
    let b = s.as_bytes();
    let mut sum = 0;
    for (i, &c) in b[..15].iter().enumerate() {
        let idx = match c {
            b'0'..=b'9' => (c - b'0') as usize,
            b'A'..=b'Z' => (c - b'A') as usize,
            _ => return false,
        };
        // Positions are 1-based in the spec: odd positions are even indices.
        sum += if i % 2 == 0 { ODD[idx] } else { idx as u32 };
    }
    b[15] == b'A' + (sum % 26) as u8
}

/// Dutch citizen service number (BSN), 9 digits, eleven-proof.
pub fn nl_bsn(d: &str) -> bool {
    let b = d.as_bytes();
    if b.iter().all(|&c| c == b'0') {
        return false;
    }
    let mut sum: i32 = 0;
    for (i, &c) in b[..8].iter().enumerate() {
        sum += (9 - i as i32) * (c - b'0') as i32;
    }
    sum -= (b[8] - b'0') as i32;
    sum % 11 == 0
}

/// ICAO 9303 check digit over `data`, compared to `check`.
fn mrz_check(data: &[u8], check: u8) -> bool {
    const W: [u32; 3] = [7, 3, 1];
    let mut sum = 0;
    for (i, &c) in data.iter().enumerate() {
        let v = match c {
            b'0'..=b'9' => (c - b'0') as u32,
            b'A'..=b'Z' => (c - b'A') as u32 + 10,
            b'<' => 0,
            _ => return false,
        };
        sum += v * W[i % 3];
    }
    check.is_ascii_digit() && sum % 10 == (check - b'0') as u32
}

/// Passport MRZ (TD3) second line, 44 chars: document, birth date, expiry and composite checks.
pub fn passport_mrz_line2(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 44 {
        return false;
    }
    let composite: Vec<u8> = [&b[0..10], &b[13..20], &b[21..43]].concat();
    mrz_check(&b[0..9], b[9])
        && mrz_check(&b[13..19], b[19])
        && mrz_check(&b[21..27], b[27])
        && mrz_check(&composite, b[43])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cards() {
        // Published processor test numbers.
        for n in ["4111111111111111", "5555555555554444", "378282246310005", "6011111111111117", "3530111333300000"] {
            assert!(card(n), "{n}");
        }
        assert!(!card("4111111111111112"));
        assert!(!card("1234567812345670")); // Luhn-valid, no issuer
    }

    #[test]
    fn ibans() {
        // Examples from the ECBS/SWIFT IBAN registry.
        for s in
            ["GB82WEST12345698765432", "DE89370400440532013000", "FR1420041010050500013M02606", "NL91ABNA0417164300"]
        {
            assert_eq!(iban_length(&s[..2]), Some(s.len()), "{s}");
            assert!(iban(s), "{s}");
        }
        assert!(!iban("GB82WEST12345698765433"));
    }

    #[test]
    fn ssn() {
        assert!(us_ssn("536224181")); // arbitrary well-formed number
        for bad in ["000123456", "666123456", "900123456", "123004567", "123450000"] {
            assert!(!us_ssn(bad), "{bad}");
        }
    }

    #[test]
    fn nino() {
        assert!(uk_nino("AB123456C"));
        assert!(!uk_nino("GB123456A"));
    }

    #[test]
    fn steuer_id() {
        // Commonly cited example number; valid under the official algorithm.
        assert!(de_steuer_id("86095742719"));
        assert!(!de_steuer_id("86095742718"));
        assert!(!de_steuer_id("12345678903")); // no repeated digit
    }

    #[test]
    fn nir() {
        assert!(fr_nir("255081416802538")); // commonly cited example NIR
        assert!(!fr_nir("255081416802539"));
        assert!(!fr_nir("1850228A1234549")); // letters outside 2A/2B
    }

    #[test]
    fn dni_nie() {
        assert!(es_dni_nie("12345678Z"));
        assert!(es_dni_nie("X1234567L"));
        assert!(!es_dni_nie("12345678A"));
    }

    #[test]
    fn codice_fiscale() {
        assert!(it_codice_fiscale("RSSMRA85T10A562S"));
        assert!(!it_codice_fiscale("RSSMRA85T10A562T"));
    }

    #[test]
    fn bsn() {
        assert!(nl_bsn("111222333"));
        assert!(nl_bsn("123456782"));
        assert!(!nl_bsn("123456789"));
    }

    #[test]
    fn mrz() {
        // ICAO Doc 9303 Part 4 specimen (Anna Maria Eriksson).
        assert!(passport_mrz_line2("L898902C36UTO7408122F1204159ZE184226B<<<<<10"));
        assert!(!passport_mrz_line2("L898902C36UTO7408122F1204159ZE184226B<<<<<11"));
    }
}
