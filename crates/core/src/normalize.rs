//! Normalization for local matching.
//!
//! Local rules run on a *shadow* copy of the text that defeats cheap evasions:
//! NFKC (full-width digits become ASCII, NBSP becomes a space), invisible format
//! characters removed, dashes folded to `-`, and `[at]` / `(dot)` folded to
//! `@` / `.`. Every shadow byte remembers which original bytes produced it, so a
//! match in the shadow maps back to an exact range of the original text.

use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Default)]
pub struct Normalized {
    pub text: String,
    /// For each byte of `text`, the original byte range that produced it.
    origin: Vec<(u32, u32)>,
}

impl Normalized {
    /// The original byte range for a shadow byte range. `start < end` required.
    pub fn original_span(&self, start: usize, end: usize) -> (usize, usize) {
        (self.origin[start].0 as usize, self.origin[end - 1].1 as usize)
    }

    /// Original byte offset where the shadow byte at `i` came from.
    pub fn original_start(&self, i: usize) -> usize {
        self.origin[i].0 as usize
    }

    fn push(&mut self, s: &str, from: usize, to: usize) {
        self.text.push_str(s);
        self.origin.extend(std::iter::repeat_n((from as u32, to as u32), s.len()));
    }

    fn push_char(&mut self, c: char, from: usize, to: usize) {
        let mut buf = [0u8; 4];
        self.push(c.encode_utf8(&mut buf), from, to);
    }
}

const FOLDS: [(&str, &str); 6] =
    [("[at]", "@"), ("(at)", "@"), ("{at}", "@"), ("[dot]", "."), ("(dot)", "."), ("{dot}", ".")];

/// Characters that render as nothing and are used to split identifiers.
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}'
        | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}'
        | '\u{E0000}'..='\u{E007F}')
}

fn is_dash(c: char) -> bool {
    matches!(c, '\u{2010}'..='\u{2015}' | '\u{2212}' | '\u{FE58}' | '\u{FE63}' | '\u{FF0D}')
}

pub fn normalize(s: &str) -> Normalized {
    let mut out = Normalized { text: String::with_capacity(s.len()), origin: Vec::with_capacity(s.len()) };
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < s.len() {
        let b = bytes[i];
        if matches!(b, b'[' | b'(' | b'{') {
            if let Some((pat, rep)) = FOLDS.iter().find(|(pat, _)| {
                bytes.len() >= i + pat.len() && bytes[i..i + pat.len()].eq_ignore_ascii_case(pat.as_bytes())
            }) {
                out.push(rep, i, i + pat.len());
                i += pat.len();
                continue;
            }
        }
        if b.is_ascii() {
            out.push_char(b as char, i, i + 1);
            i += 1;
            continue;
        }
        let c = s[i..].chars().next().expect("char boundary");
        let end = i + c.len_utf8();
        if is_invisible(c) {
            // dropped
        } else if is_dash(c) {
            out.push_char('-', i, end);
        } else {
            for n in std::iter::once(c).nfkc() {
                if !is_invisible(n) {
                    out.push_char(if is_dash(n) { '-' } else { n }, i, end);
                }
            }
        }
        i = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_and_maps_back() {
        let src = "mail: jo[at]ex(DOT)com";
        let n = normalize(src);
        assert_eq!(n.text, "mail: jo@ex.com");
        let at = n.text.find('@').unwrap();
        assert_eq!(n.original_span(at, at + 1), (8, 12));
        assert_eq!(n.original_span(6, n.text.len()), (6, src.len()));
    }

    #[test]
    fn strips_invisible_and_widens_digits() {
        let src = "4\u{200B}1\u{2060}1１";
        let n = normalize(src);
        assert_eq!(n.text, "4111");
        assert_eq!(n.original_span(0, 4), (0, src.len()));
    }

    #[test]
    fn folds_dashes_and_nbsp() {
        assert_eq!(normalize("555\u{2013}0100\u{00A0}x").text, "555-0100 x");
    }
}
