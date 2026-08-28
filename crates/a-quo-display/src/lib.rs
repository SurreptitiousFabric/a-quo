#![forbid(unsafe_code)]

//! Shared validation for text shown on A Quo security and evidence surfaces.
//!
//! The rule rejects Unicode controls, line and paragraph separators, and every
//! code point in Unicode 17.0's [`Default_Ignorable_Code_Point`] derived
//! property. Such text can disappear, reorder or structurally split nearby text,
//! or render differently between the consent surface and a verifier. Ordinary
//! combining marks and visible emoji remain valid. Emoji sequences that require
//! a zero-width joiner or variation selector are deliberately rejected on these
//! security-facing surfaces.
//!
//! [`Default_Ignorable_Code_Point`]: https://www.unicode.org/Public/17.0.0/ucd/DerivedCoreProperties.txt

/// Maximum input retained by [`escape_untrusted_bytes_for_terminal`].
pub const MAX_ESCAPED_DIAGNOSTIC_INPUT_BYTES: usize = 256;

/// Returns whether `value` contains a character unsafe for security-facing text.
#[must_use]
pub fn contains_unsafe_display_characters(value: &str) -> bool {
    value.chars().any(is_unsafe_display_character)
}

/// Produces bounded printable ASCII for diagnostics that may reach a terminal.
///
/// Printable ASCII is preserved except for quotes and backslashes. Every other
/// byte is rendered as `\xNN`; overlong input receives a trailing `...` marker.
/// The byte-oriented interface also supports non-UTF-8 paths without lossy
/// conversion.
#[must_use]
pub fn escape_untrusted_bytes_for_terminal(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let retained = bytes.len().min(MAX_ESCAPED_DIAGNOSTIC_INPUT_BYTES);
    let mut escaped = String::with_capacity(retained.saturating_mul(4).saturating_add(3));
    for &byte in &bytes[..retained] {
        match byte {
            b' '..=b'~' if !matches!(byte, b'\\' | b'\'' | b'"') => {
                escaped.push(char::from(byte));
            }
            _ => {
                escaped.push('\\');
                escaped.push('x');
                escaped.push(char::from(HEX[usize::from(byte >> 4)]));
                escaped.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
    if bytes.len() > retained {
        escaped.push_str("...");
    }
    escaped
}

/// UTF-8 convenience wrapper for [`escape_untrusted_bytes_for_terminal`].
#[must_use]
pub fn escape_untrusted_text_for_terminal(value: &str) -> String {
    escape_untrusted_bytes_for_terminal(value.as_bytes())
}

fn is_unsafe_display_character(character: char) -> bool {
    character.is_control()
        || matches!(character, '\u{2028}' | '\u{2029}')
        || is_unicode_17_default_ignorable(character)
}

/// Unicode 17.0 `Default_Ignorable_Code_Point`, represented as the complete,
/// contiguous ranges published in `DerivedCoreProperties.txt`.
///
/// Keep this table version-pinned: Unicode does not promise that this derived
/// property is stable between versions.
fn is_unicode_17_default_ignorable(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fff8}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_every_unicode_17_range_at_both_boundaries() {
        let boundaries = [
            ('\u{00ad}', '\u{00ad}'),
            ('\u{034f}', '\u{034f}'),
            ('\u{061c}', '\u{061c}'),
            ('\u{115f}', '\u{1160}'),
            ('\u{17b4}', '\u{17b5}'),
            ('\u{180b}', '\u{180f}'),
            ('\u{200b}', '\u{200f}'),
            ('\u{202a}', '\u{202e}'),
            ('\u{2060}', '\u{206f}'),
            ('\u{3164}', '\u{3164}'),
            ('\u{fe00}', '\u{fe0f}'),
            ('\u{feff}', '\u{feff}'),
            ('\u{ffa0}', '\u{ffa0}'),
            ('\u{fff0}', '\u{fff8}'),
            ('\u{1bca0}', '\u{1bca3}'),
            ('\u{1d173}', '\u{1d17a}'),
            ('\u{e0000}', '\u{e0fff}'),
        ];

        for (start, end) in boundaries {
            assert!(is_unsafe_display_character(start), "U+{:04X}", start as u32);
            assert!(is_unsafe_display_character(end), "U+{:04X}", end as u32);
        }
    }

    #[test]
    fn accepts_visible_assigned_neighbors_outside_default_ignorable_ranges() {
        for character in [
            '\u{00ac}',
            '\u{00ae}',
            '\u{034e}',
            '\u{0350}',
            '\u{061b}',
            '\u{061d}',
            '\u{1161}',
            '\u{17b6}',
            '\u{180a}',
            '\u{1810}',
            '\u{2010}',
            '\u{2070}',
            '\u{3165}',
            '\u{fe10}',
            '\u{ff9f}',
            '\u{ffa1}',
            '\u{1d172}',
            '\u{1d17b}',
        ] {
            assert!(
                !is_unsafe_display_character(character),
                "U+{:04X}",
                character as u32
            );
        }
    }

    #[test]
    fn rejects_controls_and_reported_invisible_formatting_cases() {
        for value in [
            "line\nbreak",
            "line\u{2028}separator",
            "paragraph\u{2029}separator",
            "zero\u{200b}width",
            "word\u{2060}joiner",
            "emoji\u{200d}joiner",
            "variation\u{fe0f}selector",
            "supplement\u{e0100}selector",
        ] {
            assert!(contains_unsafe_display_characters(value), "{value:?}");
        }
    }

    #[test]
    fn accepts_visible_text_combining_marks_and_base_emoji() {
        for value in [
            "Cafe\u{0301}",
            "नमस्ते",
            "Publisher 😀",
            "Swiss flag 🇨🇭",
            "Thumbs up 👍🏽",
        ] {
            assert!(!contains_unsafe_display_characters(value), "{value:?}");
        }
    }

    #[test]
    fn terminal_diagnostics_are_ascii_exact_and_bounded() {
        assert_eq!(
            escape_untrusted_bytes_for_terminal(b"safe /.-_"),
            "safe /.-_"
        );
        assert_eq!(
            escape_untrusted_text_for_terminal("quote'\" slash\\ line\n bidi\u{202e}"),
            "quote\\x27\\x22 slash\\x5c line\\x0a bidi\\xe2\\x80\\xae"
        );
        assert!(escape_untrusted_bytes_for_terminal(&[0xff]).is_ascii());

        let escaped = escape_untrusted_bytes_for_terminal(&vec![
            0xff;
            MAX_ESCAPED_DIAGNOSTIC_INPUT_BYTES
                + 1
        ]);
        assert!(escaped.is_ascii());
        assert!(escaped.ends_with("..."));
        assert_eq!(escaped.len(), MAX_ESCAPED_DIAGNOSTIC_INPUT_BYTES * 4 + 3);
    }
}
