#![forbid(unsafe_code)]

//! Deterministic, secret-free renderers for an A Quo persona-root card.
//!
//! A root card is a self-asserted comparison aid copied from a persona root. It
//! is not a root proof, an independent pin, legal identity, current
//! authorization, or a safety verdict. The QR code contains only the complete
//! root-statement SHA-256 pin URI.

use std::error::Error;
use std::fmt::{self, Write as _};

use a_quo_core::{PersonaRootCard, ProofError, validate_persona_root_card};
use qrcode::{Color, EcLevel, QrCode};

pub const MAX_ROOT_CARD_TEXT_BYTES: usize = 8 * 1024;
pub const MAX_ROOT_CARD_HTML_BYTES: usize = 64 * 1024;

const SHA256_HEX_LENGTH: usize = 64;
const QR_QUIET_ZONE_MODULES: usize = 4;

#[derive(Debug)]
pub enum RootCardError {
    Core(ProofError),
    QrEncoding(String),
    OutputTooLarge {
        format: &'static str,
        actual: usize,
        maximum: usize,
    },
}

impl fmt::Display for RootCardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(formatter, "persona-root card validation failed: {error}"),
            Self::QrEncoding(reason) => write!(formatter, "cannot encode root pin QR: {reason}"),
            Self::OutputTooLarge {
                format,
                actual,
                maximum,
            } => write!(
                formatter,
                "rendered {format} root card is {actual} bytes; maximum is {maximum} bytes"
            ),
        }
    }
}

impl Error for RootCardError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::QrEncoding(_) | Self::OutputTooLarge { .. } => None,
        }
    }
}

impl From<ProofError> for RootCardError {
    fn from(error: ProofError) -> Self {
        Self::Core(error)
    }
}

pub type Result<T> = std::result::Result<T, RootCardError>;

/// Render accessible UTF-8 text with no ANSI escapes or terminal control
/// sequences. The QR URI and full digest are both visible as text.
///
/// This validates the closed [`PersonaRootCard`] format, including its copied
/// root fields, digest, and pin URI, but it does not verify a root signature.
/// Signature verification requires the corresponding persona-root proof.
pub fn render_root_card_text(card: &PersonaRootCard) -> Result<String> {
    validate_persona_root_card(card)?;
    let mut output = String::with_capacity(2 * 1024);
    writeln!(output, "A Quo persona root card v1").expect("writing to String cannot fail");
    writeln!(output, "==========================").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "Root identity: SELF-ASSERTED").expect("writing to String cannot fail");
    writeln!(output, "Persona: {}", card.persona).expect("writing to String cannot fail");
    writeln!(output, "Persona anchor: {}", card.persona_anchor)
        .expect("writing to String cannot fail");
    writeln!(output, "Root version: {}", card.root_version).expect("writing to String cannot fail");
    writeln!(
        output,
        "Root's self-asserted issuance time (Unix): {}",
        card.issued_at
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "Initial key fingerprint: {}",
        card.initial_key_fingerprint
    )
    .expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "Root statement SHA-256 (complete, grouped):")
        .expect("writing to String cannot fail");
    writeln!(output, "{}", grouped_sha256(&card.root_statement_sha256))
        .expect("writing to String cannot fail");
    writeln!(output, "Root statement SHA-256 (complete, ungrouped):")
        .expect("writing to String cannot fail");
    writeln!(output, "{}", card.root_statement_sha256).expect("writing to String cannot fail");
    writeln!(output, "QR pin URI (complete):").expect("writing to String cannot fail");
    writeln!(output, "{}", card.pin_uri).expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    writeln!(
        output,
        "The QR is a convenience for comparing this complete digest. It is not authentication."
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "Use a separately trusted route if you need an independent root pin."
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "This card contains public verification data only; it contains no private key, recovery secret, wallet credential, or signer locator."
    )
    .expect("writing to String cannot fail");
    writeln!(output, "Not established:").expect("writing to String cannot fail");
    writeln!(output, "- legal or government identity").expect("writing to String cannot fail");
    writeln!(output, "- an independent pin source").expect("writing to String cannot fail");
    writeln!(
        output,
        "- current authorization or the latest continuity head"
    )
    .expect("writing to String cannot fail");
    writeln!(output, "- truth, originality, or artifact safety")
        .expect("writing to String cannot fail");

    bound_output("plain text", output, MAX_ROOT_CARD_TEXT_BYTES)
}

/// Render a standalone printable HTML document with an inline black-and-white
/// SVG QR. It contains no script or external resource reference.
///
/// This validates the closed [`PersonaRootCard`] format, including its copied
/// root fields, digest, and pin URI, but it does not verify a root signature.
/// Signature verification requires the corresponding persona-root proof.
pub fn render_root_card_html(card: &PersonaRootCard) -> Result<String> {
    validate_persona_root_card(card)?;
    let qr = build_qr(&card.pin_uri)?;
    let qr_svg = render_qr_svg(&qr, &card.pin_uri);
    let mut output = String::with_capacity(48 * 1024);
    output.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
    output.push_str("<meta charset=\"utf-8\">\n");
    output.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    output.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; connect-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none'\">\n");
    output.push_str("<title>A Quo persona root card</title>\n");
    output.push_str("<style>\n");
    output.push_str(HTML_STYLE);
    output.push_str("</style>\n</head>\n<body>\n<main>\n");
    output.push_str("<header><p class=\"eyebrow\">A Quo persona root card v1</p><h1>Self-asserted persona root</h1><p class=\"lead\">Use this card to compare one complete root digest. A separate trusted route is still required for an independent pin.</p></header>\n");
    output.push_str("<section aria-labelledby=\"identity-heading\"><h2 id=\"identity-heading\">Root facts</h2><dl>\n");
    output.push_str("<dt>Persona</dt><dd><bdi dir=\"auto\">");
    push_html_escaped(&mut output, &card.persona);
    output.push_str("</bdi></dd>\n<dt>Persona anchor</dt><dd><code class=\"ltr\" dir=\"ltr\">");
    push_html_escaped(&mut output, &card.persona_anchor);
    output.push_str("</code></dd>\n<dt>Root version</dt><dd>");
    write!(output, "{}", card.root_version).expect("writing to String cannot fail");
    output.push_str("</dd>\n<dt>Root's self-asserted issuance time</dt><dd><span class=\"ltr\" dir=\"ltr\">Unix ");
    write!(output, "{}", card.issued_at).expect("writing to String cannot fail");
    output.push_str(
        "</span></dd>\n<dt>Initial key fingerprint</dt><dd><code class=\"ltr wrap\" dir=\"ltr\">",
    );
    push_html_escaped(&mut output, &card.initial_key_fingerprint);
    output.push_str("</code></dd>\n</dl></section>\n");
    output.push_str("<section aria-labelledby=\"pin-heading\"><h2 id=\"pin-heading\">Complete root pin</h2><p class=\"label\">SHA-256, grouped for reading</p><p><code class=\"digest ltr wrap\" dir=\"ltr\">");
    push_html_escaped(&mut output, &grouped_sha256(&card.root_statement_sha256));
    output.push_str("</code></p><p class=\"label\">SHA-256, canonical ungrouped form</p><p><code class=\"digest ltr wrap\" dir=\"ltr\">");
    push_html_escaped(&mut output, &card.root_statement_sha256);
    output.push_str("</code></p><div class=\"qr\">");
    output.push_str(&qr_svg);
    output.push_str("</div><p class=\"label\">QR pin URI, also shown as text</p><p><code class=\"ltr wrap\" dir=\"ltr\">");
    push_html_escaped(&mut output, &card.pin_uri);
    output.push_str("</code></p><p>The QR contains only that complete digest URI. It is a scanning convenience, not authentication.</p></section>\n");
    output.push_str("<section aria-labelledby=\"limits-heading\"><h2 id=\"limits-heading\">What this card does not establish</h2><ul><li>legal or government identity</li><li>an independent pin source</li><li>current authorization or the latest continuity head</li><li>truth, originality, or artifact safety</li></ul><p>This self-asserted card contains public verification data only. It contains no private key, recovery secret, wallet credential, or signer locator.</p></section>\n");
    output.push_str("</main>\n</body>\n</html>\n");

    bound_output("HTML", output, MAX_ROOT_CARD_HTML_BYTES)
}

const HTML_STYLE: &str = r#"
:root { color-scheme: light; }
* { box-sizing: border-box; }
html { background: #fff; color: #000; }
body { margin: 0; background: #fff; color: #000; line-height: 1.45; }
main { max-width: 52rem; margin: 0 auto; padding: 2rem; }
header, section { border: 2px solid #000; padding: 1.25rem; margin: 0 0 1.25rem; break-inside: avoid; }
h1, h2, p { margin-top: 0; }
.eyebrow, .label { font-weight: 700; }
.lead { font-size: 1.1rem; }
dl { display: grid; grid-template-columns: minmax(9rem, 1fr) minmax(0, 2fr); gap: .65rem 1rem; margin: 0; }
dt { font-weight: 700; }
dd { margin: 0; min-width: 0; }
.ltr { direction: ltr; unicode-bidi: isolate; text-align: left; }
.wrap { overflow-wrap: anywhere; word-break: break-word; }
.digest { font-size: 1.05rem; font-weight: 700; letter-spacing: .035em; }
.qr { width: min(100%, 28rem); margin: 1rem auto; }
.qr svg { display: block; width: 100%; height: auto; background: #fff; border: 1px solid #000; }
@media print {
  @page { margin: 12mm; }
  body { background: #fff !important; color: #000 !important; }
  main { max-width: none; padding: 0; }
  header, section { border-color: #000; }
}
"#;

fn grouped_sha256(value: &str) -> String {
    debug_assert_eq!(value.len(), SHA256_HEX_LENGTH);
    let (groups, remainder) = value.as_bytes().as_chunks::<4>();
    debug_assert!(remainder.is_empty());
    groups
        .iter()
        .map(|chunk| std::str::from_utf8(chunk).expect("SHA-256 hex is ASCII"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn build_qr(pin_uri: &str) -> Result<QrCode> {
    QrCode::with_error_correction_level(pin_uri.as_bytes(), EcLevel::H)
        .map_err(|error| RootCardError::QrEncoding(error.to_string()))
}

fn render_qr_svg(qr: &QrCode, pin_uri: &str) -> String {
    let width = qr.width();
    let canvas_width = width + 2 * QR_QUIET_ZONE_MODULES;
    let colors = qr.to_colors();
    let mut path = String::with_capacity(colors.len().saturating_mul(14));
    for (index, color) in colors.iter().enumerate() {
        if *color == Color::Dark {
            let x = index % width + QR_QUIET_ZONE_MODULES;
            let y = index / width + QR_QUIET_ZONE_MODULES;
            write!(path, "M{x} {y}h1v1h-1z").expect("writing to String cannot fail");
        }
    }

    let mut svg = String::with_capacity(path.len() + pin_uri.len() + 512);
    write!(
        svg,
        "<svg role=\"img\" aria-labelledby=\"aquo-qr-title aquo-qr-desc\" viewBox=\"0 0 {canvas_width} {canvas_width}\" shape-rendering=\"crispEdges\"><title id=\"aquo-qr-title\">A Quo root pin QR code</title><desc id=\"aquo-qr-desc\">Complete digest-only pin URI: "
    )
    .expect("writing to String cannot fail");
    push_html_escaped(&mut svg, pin_uri);
    write!(
        svg,
        "</desc><rect width=\"{canvas_width}\" height=\"{canvas_width}\" fill=\"#fff\"/><path d=\"{path}\" fill=\"#000\"/></svg>"
    )
    .expect("writing to String cannot fail");
    svg
}

fn push_html_escaped(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            character if character.is_control() => {
                write!(output, "&#x{:X};", u32::from(character))
                    .expect("writing to String cannot fail");
            }
            character => output.push(character),
        }
    }
}

fn bound_output(format: &'static str, output: String, maximum: usize) -> Result<String> {
    let actual = output.len();
    if actual <= maximum {
        Ok(output)
    } else {
        Err(RootCardError::OutputTooLarge {
            format,
            actual,
            maximum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use a_quo_core::{
        PERSONA_ROOT_CARD_SCHEMA, PERSONA_ROOT_PIN_URI_PREFIX, PersonaRootStatement,
        canonical_persona_root_card_bytes, new_persona_root_statement_with_anchor,
        persona_root_statement_sha256,
    };

    const ANCHOR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2wZ6f9bI6YlF1YyW5iU+a4jvfp9DCf3j6PYfnT1rYA";

    fn card(persona: &str) -> PersonaRootCard {
        let statement =
            new_persona_root_statement_with_anchor(ANCHOR, persona, 1_700_000_000, PUBLIC_KEY)
                .unwrap();
        card_from_statement(statement)
    }

    fn card_from_statement(statement: PersonaRootStatement) -> PersonaRootCard {
        let root_statement_sha256 = persona_root_statement_sha256(&statement).unwrap();
        PersonaRootCard {
            schema: PERSONA_ROOT_CARD_SCHEMA.to_owned(),
            canonicalization: "RFC8785".to_owned(),
            persona: statement.persona,
            persona_anchor: statement.persona_anchor,
            root_version: statement.root_version,
            issued_at: statement.issued_at,
            initial_key_fingerprint: statement.initial_key_fingerprint,
            pin_uri: format!("{PERSONA_ROOT_PIN_URI_PREFIX}{root_statement_sha256}"),
            root_statement_sha256,
        }
    }

    #[test]
    fn renderers_are_deterministic_bounded_and_show_complete_values() {
        let card = card("Juniper Quill");
        let text = render_root_card_text(&card).unwrap();
        let html = render_root_card_html(&card).unwrap();

        assert_eq!(text, render_root_card_text(&card).unwrap());
        assert_eq!(html, render_root_card_html(&card).unwrap());
        assert!(text.len() <= MAX_ROOT_CARD_TEXT_BYTES);
        assert!(html.len() <= MAX_ROOT_CARD_HTML_BYTES);

        for output in [&text, &html] {
            assert!(output.contains(&card.root_statement_sha256));
            assert!(output.contains(&card.pin_uri));
            assert!(output.contains("Juniper Quill"));
        }
        assert!(text.contains(&grouped_sha256(&card.root_statement_sha256)));
        assert!(html.contains(&grouped_sha256(&card.root_statement_sha256)));
    }

    #[test]
    fn core_is_the_only_card_format_owner() {
        let card = card("Format Publisher");
        let canonical = canonical_persona_root_card_bytes(&card).unwrap();

        assert_eq!(card.schema, PERSONA_ROOT_CARD_SCHEMA);
        assert_eq!(card.schema, "urn:a-quo:persona-root-card:v1");
        assert!(canonical.starts_with(b"{"));
        assert!(canonical.ends_with(b"}"));
        assert!(!canonical.contains(&b'\n'));
    }

    #[test]
    fn qr_payload_is_digest_only_high_correction_and_has_a_quiet_zone() {
        let card = card("QR Publisher");
        let expected = format!(
            "{PERSONA_ROOT_PIN_URI_PREFIX}{}",
            card.root_statement_sha256
        );
        assert_eq!(card.pin_uri, expected);
        assert_eq!(
            card.pin_uri.len(),
            PERSONA_ROOT_PIN_URI_PREFIX.len() + SHA256_HEX_LENGTH
        );
        let qr = build_qr(&card.pin_uri).unwrap();
        let expected_qr =
            QrCode::with_error_correction_level(expected.as_bytes(), EcLevel::H).unwrap();
        assert_eq!(qr.error_correction_level(), EcLevel::H);
        assert_eq!(qr.to_colors(), expected_qr.to_colors());
        let svg = render_qr_svg(&qr, &card.pin_uri);
        let canvas = qr.width() + 2 * QR_QUIET_ZONE_MODULES;
        assert!(svg.contains(&format!("viewBox=\"0 0 {canvas} {canvas}\"")));
        assert!(svg.contains(&card.pin_uri));
        assert!(svg.contains("fill=\"#fff\""));
        assert!(svg.contains("fill=\"#000\""));
    }

    #[test]
    fn hostile_markup_is_escaped_and_rtl_text_is_isolated_without_truncation() {
        let persona = "<script>alert(&quot;owned&quot;)</script> & \"quote\" 'single' العربية";
        let card = card(persona);
        let html = render_root_card_html(&card).unwrap();
        let text = render_root_card_text(&card).unwrap();

        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&amp;quot;"));
        assert!(html.contains("&quot;quote&quot;"));
        assert!(html.contains("&#39;single&#39;"));
        assert!(html.contains("<bdi dir=\"auto\">"));
        assert!(html.contains("العربية"));
        assert!(text.contains(persona));
    }

    #[test]
    fn controls_are_escaped_defensively_and_rejected_by_root_validation() {
        let mut escaped = String::new();
        push_html_escaped(&mut escaped, "line\nbreak\u{0000}");
        assert_eq!(escaped, "line&#xA;break&#x0;");
        assert!(
            new_persona_root_statement_with_anchor(
                ANCHOR,
                "line\nbreak",
                1_700_000_000,
                PUBLIC_KEY,
            )
            .is_err()
        );
    }

    #[test]
    fn maximum_length_visible_label_stays_within_every_bound() {
        let persona = "<".repeat(256);
        let card = card(&persona);
        let text = render_root_card_text(&card).unwrap();
        let html = render_root_card_html(&card).unwrap();

        assert!(text.len() <= MAX_ROOT_CARD_TEXT_BYTES);
        assert!(html.len() <= MAX_ROOT_CARD_HTML_BYTES);
        assert_eq!(html.matches("&lt;").count(), 256);
        assert!(text.contains(&persona));
    }

    #[test]
    fn html_is_standalone_semantic_printable_and_has_no_remote_references() {
        let html = render_root_card_html(&card("Accessible Publisher")).unwrap();

        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<main>"));
        assert!(html.contains("<h1>Self-asserted persona root</h1>"));
        assert!(html.contains("<h2 id=\"pin-heading\">Complete root pin</h2>"));
        assert!(html.contains("role=\"img\""));
        assert!(html.contains("<title id=\"aquo-qr-title\">"));
        assert!(html.contains("<desc id=\"aquo-qr-desc\">"));
        assert!(html.contains("@media print"));
        assert!(html.contains("background: #fff"));
        assert!(html.contains("color: #000"));
        assert!(html.contains("not authentication"));
        assert!(html.contains("legal or government identity"));
        assert!(html.contains("current authorization"));
        for forbidden in [
            "<script",
            "javascript:",
            "http://",
            "https://",
            "src=",
            "href=",
            "@import",
            "url(",
            "<img",
            "<link",
            "<iframe",
            "<object",
        ] {
            assert!(!html.contains(forbidden), "found {forbidden}");
        }
    }

    #[test]
    fn malformed_core_card_fails_before_rendering() {
        let mut card = card("Mismatch");
        card.pin_uri = format!("{PERSONA_ROOT_PIN_URI_PREFIX}{}", "0".repeat(64));

        assert!(matches!(
            render_root_card_text(&card),
            Err(RootCardError::Core(_))
        ));
        assert!(matches!(
            render_root_card_html(&card),
            Err(RootCardError::Core(_))
        ));
    }

    #[test]
    fn outputs_contain_no_secret_fields_or_references() {
        let card = card("Public Facts");
        let outputs = [
            render_root_card_text(&card).unwrap(),
            render_root_card_html(&card).unwrap(),
        ];

        for output in outputs {
            for forbidden in [
                "private_key",
                "signer_locator",
                "recovery_secret",
                "wallet_credential",
                "seed_phrase",
                "http://",
                "https://",
            ] {
                assert!(!output.contains(forbidden), "found {forbidden}");
            }
        }
    }

    #[test]
    fn output_bound_error_reports_format_and_exact_limit() {
        let oversized = "x".repeat(MAX_ROOT_CARD_TEXT_BYTES + 1);
        assert!(matches!(
            bound_output("test", oversized, MAX_ROOT_CARD_TEXT_BYTES),
            Err(RootCardError::OutputTooLarge {
                format: "test",
                maximum: MAX_ROOT_CARD_TEXT_BYTES,
                ..
            })
        ));
    }
}
