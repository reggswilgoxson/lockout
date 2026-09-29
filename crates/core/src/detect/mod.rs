//! Local rules: deterministic detectors for structured identifiers.
//!
//! Each detector is a regex prefilter plus a validator, run on normalized text.
//! Detectors must keep their match *and* any context they read (keyword gates)
//! within [`MAX_CONTEXT`] bytes, which is what the segmenter's overlap tail
//! guarantees to see whole.

pub mod checksum;

use regex::Regex;

use crate::policy::Category;

/// The longest span, in normalized bytes, that a bounded detector reads:
/// an MRZ line is 44 bytes, a keyword-gated ID reads up to 40 bytes back plus
/// an 11-digit number. The segment overlap must be at least this.
pub const MAX_CONTEXT: usize = 64;

/// A match in normalized text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    pub category: Category,
    /// Detector id, e.g. `email` or a custom identifier name.
    pub id: String,
    pub start: usize,
    pub end: usize,
}

/// Values that are never findings.
#[derive(Clone, Debug, Default)]
pub struct Allow {
    /// Exact email addresses, compared case-insensitively.
    pub emails: Vec<String>,
    /// Domains whose addresses (and subdomains) are allowed.
    pub domains: Vec<String>,
    /// Phone numbers, compared by digits only.
    pub phones: Vec<String>,
}

/// RFC 2606 / RFC 6761 reserved names, and hosts that appear in code samples.
const RESERVED_DOMAINS: [&str; 3] = ["example.com", "example.net", "example.org"];
const RESERVED_TLDS: [&str; 4] = ["example", "test", "invalid", "localhost"];
const CODE_HOST_ADDRESSES: [&str; 3] = ["git@github.com", "git@gitlab.com", "git@bitbucket.org"];
/// File extensions that look like TLDs in names such as `icon@2x.png`.
const FILE_EXTENSIONS: [&str; 14] =
    ["png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js", "ts", "json", "md", "txt", "pdf"];

/// Published payment test numbers (Stripe, Braintree, Adyen documentation).
const TEST_CARDS: [&str; 12] = [
    "4111111111111111",
    "4242424242424242",
    "4012888888881881",
    "4000056655665556",
    "5555555555554444",
    "5105105105105100",
    "2223003122003222",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "6011000990139424",
    "3530111333300000",
];

/// SSNs that are public examples or were voided after appearing in advertising.
const EXAMPLE_SSNS: [&str; 3] = ["078051120", "219099999", "123456789"];

/// Cheap to clone: compiled patterns are shared.
#[derive(Clone)]
pub struct Detectors {
    email: Regex,
    phone_intl: Regex,
    phone_nanp: Regex,
    phone_national: Regex,
    card: Regex,
    iban: Regex,
    ssn: Regex,
    nino: Regex,
    steuer_id: Regex,
    nir: Regex,
    dni_nie: Regex,
    codice_fiscale: Regex,
    bsn: Regex,
    mrz: Regex,
    steuer_keywords: Regex,
    bsn_keywords: Regex,
    custom: Vec<(String, Regex)>,
    allow: Allow,
}

/// A check-digit or format check on an identifier with separators removed.
type Validator = fn(&str) -> bool;

/// Built-in patterns are ASCII-only (`\b`, `\d`): the text is already
/// normalized, and ASCII semantics keep the regex engine on its fast path.
fn re(pattern: &str) -> Regex {
    Regex::new(&format!("(?-u){pattern}")).expect("built-in pattern compiles")
}

fn strip(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '<').collect()
}

impl Detectors {
    /// `custom` maps identifier names to patterns; matches are `employee_ref`.
    pub fn new(allow: Allow, custom: Vec<(String, Regex)>) -> Detectors {
        Detectors {
            email: re(r"(?i)\b[a-z0-9][a-z0-9._%+-]{0,63}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b"),
            phone_intl: re(r"\+\d{1,3}(?:[ .-]?\(?\d{1,4}\)?){2,5}\b"),
            phone_nanp: re(r"(?:\b|\()\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b"),
            phone_national: re(r"\b0\d{1,4}[ -]\d{3,4}[ -]?\d{3,4}\b"),
            card: re(r"\b\d(?:[ -]?\d){12,18}\b"),
            iban: re(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b"),
            ssn: re(r"\b(\d{3})([ -])(\d{2})([ -])(\d{4})\b"),
            nino: re(r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b"),
            steuer_id: re(r"\b[1-9]\d ?\d{3} ?\d{3} ?\d{3}\b"),
            nir: re(r"\b[12] ?\d{2} ?\d{2} ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b"),
            dni_nie: re(r"\b(?:\d{8}|[XYZ]-?\d{7})-?[A-Z]\b"),
            codice_fiscale: re(r"\b[A-Z]{6}[0-9LMNP-V]{2}[A-EHLMPR-T][0-9LMNP-V]{2}[A-Z][0-9LMNP-V]{3}[A-Z]\b"),
            bsn: re(r"\b\d{4}\.?\d{2}\.?\d{3}\b"),
            mrz: re(r"[A-Z0-9<]{9}\d[A-Z<]{3}\d{7}[MFX<]\d{7}[A-Z0-9<]{14}[\d<]\d"),
            steuer_keywords: re(r"(?i)steuer|idnr|identifikationsnummer|tax[ -]?id|\btin\b"),
            bsn_keywords: re(r"(?i)\bbsn\b|burgerservicenummer|sofinummer|citizen service number"),
            custom,
            allow,
        }
    }

    pub fn scan(&self, text: &str) -> Vec<Detection> {
        let mut out = Vec::new();
        let mut hit = |category, id: &str, start: usize, end: usize| {
            out.push(Detection { category, id: id.to_string(), start, end });
        };

        for m in self.email.find_iter(text) {
            if !self.email_allowed(m.as_str()) {
                hit(Category::Contact, "email", m.start(), m.end());
            }
        }
        for (re, id) in [(&self.phone_intl, "phone"), (&self.phone_nanp, "phone"), (&self.phone_national, "phone")] {
            for m in re.find_iter(text) {
                if self.phone_valid(re, m.as_str()) {
                    hit(Category::Contact, id, m.start(), m.end());
                }
            }
        }
        for m in self.card.find_iter(text) {
            let d = strip(m.as_str());
            if checksum::card(&d) && !TEST_CARDS.contains(&d.as_str()) {
                hit(Category::Financial, "payment_card", m.start(), m.end());
            }
        }
        for m in self.iban.find_iter(text) {
            if let Some(len) = self.valid_iban_prefix(m.as_str()) {
                hit(Category::Financial, "iban", m.start(), m.start() + len);
            }
        }
        for c in self.ssn.captures_iter(text) {
            let m = c.get(0).unwrap();
            let d = strip(m.as_str());
            if c[2] == c[4] && checksum::us_ssn(&d) && !EXAMPLE_SSNS.contains(&d.as_str()) {
                hit(Category::GovernmentId, "us_ssn", m.start(), m.end());
            }
        }
        let validated: [(&Regex, Validator, &str); 5] = [
            (&self.nino, checksum::uk_nino, "uk_nino"),
            (&self.nir, checksum::fr_nir, "fr_nir"),
            (&self.dni_nie, checksum::es_dni_nie, "es_dni_nie"),
            (&self.codice_fiscale, checksum::it_codice_fiscale, "it_codice_fiscale"),
            (&self.mrz, checksum::passport_mrz_line2, "passport_mrz"),
        ];
        for (re, valid, id) in validated {
            for m in re.find_iter(text) {
                if valid(&strip(m.as_str())) {
                    hit(Category::GovernmentId, id, m.start(), m.end());
                }
            }
        }
        let gated: [(&Regex, &Regex, Validator, &str); 2] = [
            (&self.steuer_id, &self.steuer_keywords, checksum::de_steuer_id, "de_steuer_id"),
            (&self.bsn, &self.bsn_keywords, checksum::nl_bsn, "nl_bsn"),
        ];
        for (re, keywords, valid, id) in gated {
            for m in re.find_iter(text) {
                let from = floor_boundary(text, m.start().saturating_sub(40));
                if keywords.is_match(&text[from..m.start()]) && valid(&strip(m.as_str())) {
                    hit(Category::GovernmentId, id, m.start(), m.end());
                }
            }
        }
        for (name, re) in &self.custom {
            for m in re.find_iter(text) {
                hit(Category::EmployeeRef, name, m.start(), m.end());
            }
        }
        out.sort_by_key(|d| (d.start, d.end));
        out
    }

    fn email_allowed(&self, email: &str) -> bool {
        let email = email.to_ascii_lowercase();
        let domain = email.rsplit_once('@').map_or("", |(_, d)| d);
        let tld = domain.rsplit('.').next().unwrap_or("");
        let under = |d: &str| domain == d || domain.ends_with(&format!(".{d}"));
        CODE_HOST_ADDRESSES.contains(&email.as_str())
            || FILE_EXTENSIONS.contains(&tld)
            || RESERVED_TLDS.contains(&tld)
            || RESERVED_DOMAINS.iter().any(|d| under(d))
            || self.allow.domains.iter().any(|d| under(&d.to_ascii_lowercase()))
            || self.allow.emails.iter().any(|e| e.eq_ignore_ascii_case(&email))
    }

    fn phone_valid(&self, re: &Regex, s: &str) -> bool {
        let digits: String = s.chars().filter(char::is_ascii_digit).collect();
        if self.allow.phones.iter().any(|p| p.chars().filter(char::is_ascii_digit).collect::<String>() == digits) {
            return false;
        }
        if std::ptr::eq(re, &self.phone_intl) {
            return (8..=15).contains(&digits.len());
        }
        if std::ptr::eq(re, &self.phone_nanp) {
            let b = digits.as_bytes();
            // Area and exchange start 2-9; 555-0100..0199 is reserved for fiction;
            // toll-free numbers are business lines, not personal ones.
            let fictional = &digits[3..6] == "555" && &digits[6..8] == "01";
            let toll_free = matches!(&digits[..3], "800" | "833" | "844" | "855" | "866" | "877" | "888");
            return b[0] >= b'2' && b[3] >= b'2' && !fictional && !toll_free;
        }
        (10..=11).contains(&digits.len())
    }

    /// The IBAN regex may run into following words; validate the prefix of
    /// the country's length. Returns the length in bytes of the valid prefix.
    fn valid_iban_prefix(&self, s: &str) -> Option<usize> {
        let len = checksum::iban_length(&s[..2])?;
        let mut compact = String::new();
        for (i, c) in s.char_indices() {
            if c != ' ' {
                compact.push(c);
            }
            if compact.len() == len {
                return checksum::iban(&compact).then_some(i + c.len_utf8());
            }
        }
        None
    }
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(text: &str) -> Vec<String> {
        Detectors::new(Allow::default(), vec![]).scan(text).into_iter().map(|d| d.id).collect()
    }

    #[test]
    fn finds_each_kind() {
        let cases = [
            ("write to dave.miller@acme-corp.com today", "email"),
            ("call +44 20 7946 0958 now", "phone"),
            ("cell (312) 555-2368 ok", "phone"),
            ("ring 030 1234 5678 now", "phone"),
            ("card 4556 7375 8689 9855 exp", "payment_card"),
            ("iban DE89 3704 0044 0532 0130 00 thanks", "iban"),
            ("ssn 536-22-4181.", "us_ssn"),
            ("NI number AB 12 34 56 C.", "uk_nino"),
            ("Steuer-ID: 86 095 742 719", "de_steuer_id"),
            ("NIR 2 55 08 14 168 025 38", "fr_nir"),
            ("DNI 12345678Z", "es_dni_nie"),
            ("CF RSSMRA85T10A562S", "it_codice_fiscale"),
            ("BSN 111222333", "nl_bsn"),
            ("L898902C36UTO7408122F1204159ZE184226B<<<<<10", "passport_mrz"),
        ];
        for (text, id) in cases {
            assert_eq!(ids(text), vec![id.to_string()], "{text}");
        }
    }

    #[test]
    fn ignores_documented_examples_and_code() {
        for text in [
            "email user@example.com or ops@mail.example.org",
            "git clone git@github.com:acme/lockout.git",
            "logo@2x.png",
            "test card 4111 1111 1111 1111",
            "call 555-0123 or (212) 555-0199",
            "NI number QQ 12 34 56 C",
            "SSN 123-45-6789",
            "9 digits 111222333 without a keyword",
            "Steuer 12345678901",
            "UUID 3f2c9a1e-8b7d-4c21-9f0e-5a6b7c8d9e0f",
            "released 2024-03-15 10:42:07, version 1.24.3",
            "CAS 7440-43-9, UN 1203, ISO 45001:2018, 29 CFR 1910.1200",
        ] {
            assert!(ids(text).is_empty(), "{text}: {:?}", ids(text));
        }
    }

    #[test]
    fn iban_does_not_swallow_following_words() {
        let text = "DE89 3704 0044 0532 0130 00 AND MORE";
        let d = Detectors::new(Allow::default(), vec![]).scan(text);
        assert_eq!(&text[d[0].start..d[0].end], "DE89 3704 0044 0532 0130 00");
    }

    #[test]
    fn allowlist_and_custom_identifiers() {
        let allow =
            Allow { emails: vec!["safety@acme.com".into()], domains: vec![], phones: vec!["+1 800 555 0100".into()] };
        let custom = vec![("employee_id".to_string(), Regex::new(r"\bE\d{6}\b").unwrap())];
        let d = Detectors::new(allow, custom).scan("Email Safety@acme.com or 1-800-555-0100. Badge E123456.");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].category, Category::EmployeeRef);
    }
}
