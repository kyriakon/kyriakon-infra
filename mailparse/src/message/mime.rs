//! RFC 2046 multipart walking.
//!
//! A boundary is a delimiter line, not a substring: it must occupy a whole
//! line, begin with `--`, and the boundary value must satisfy RFC 2046's
//! `bchars`. The walk therefore cannot be moved by text inside a part that
//! merely mentions a boundary or a Content-Type.

use super::header::{lines, lines_from, split_message};
use crate::Malformed;

/// The most parts a walk will collect. A report or an RFC 3156 envelope has a
/// handful; a message with millions of delimiter lines is a memory amplifier,
/// not mail, and is refused before the vector grows.
const MAX_PARTS: usize = 1024;

/// One body part: its header block, the empty line that ends it, and its body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Part<'a> {
    pub headers: &'a [u8],
    pub separator: &'a [u8],
    /// The part body without the line ending that introduces the delimiter.
    pub body: &'a [u8],
    /// The body and that line ending, for a caller that must keep the bytes it
    /// was given, such as an armoured message that needs its final newline.
    pub body_with_ending: &'a [u8],
}

/// The parts of a multipart body and the epilogue after the closing delimiter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Multipart<'a> {
    pub parts: Vec<Part<'a>>,
    pub epilogue: &'a [u8],
}

/// Walk a multipart body with `boundary`.
///
/// The preamble before the opening delimiter and the epilogue after the closing
/// one are ignored, as RFC 2046 says. Each part's body ends at its delimiter
/// line, with the line ending that introduces the delimiter excluded, so a part
/// body does not carry the separator that belongs to the boundary. The
/// epilogue is returned because a caller that rebuilds a wrapper must decide
/// whether trailing bytes are allowed.
pub fn walk_multipart<'a>(body: &'a [u8], boundary: &str) -> Result<Multipart<'a>, Malformed> {
    if !valid_boundary(boundary) {
        return Err(Malformed::new("not an RFC 2046 boundary"));
    }
    let open = format!("--{boundary}");
    let close = format!("--{boundary}--");

    let mut first = None;
    for line in lines(body) {
        if is_delimiter(line.text, &open) {
            first = Some((line, false));
            break;
        }
        if is_delimiter(line.text, &close) {
            first = Some((line, true));
            break;
        }
    }
    let Some((opening, closes_first)) = first else {
        return Err(Malformed::new("no MIME boundary line"));
    };
    if closes_first {
        return Err(Malformed::new("MIME boundary closes before it opens"));
    }

    let mut parts = Vec::new();
    let mut part_start = opening.next;
    for line in lines_from(body, opening.next) {
        let closes = is_delimiter(line.text, &close);
        if !closes && !is_delimiter(line.text, &open) {
            continue;
        }
        if parts.len() == MAX_PARTS {
            return Err(Malformed::new("too many MIME parts"));
        }
        let end = part_end(body, part_start, line.start)?;
        let message = split_message(&body[part_start..end])?;
        let body_start = part_start + message.headers.len() + message.separator.len();
        parts.push(Part {
            headers: message.headers,
            separator: message.separator,
            body: message.body,
            body_with_ending: &body[body_start..line.start],
        });
        if closes {
            return Ok(Multipart {
                parts,
                epilogue: &body[line.next..],
            });
        }
        part_start = line.next;
    }
    Err(Malformed::new("MIME boundary does not close"))
}

/// The first `boundary` parameter of a Content-Type header value.
///
/// The value is scanned as parameters rather than split on `;`, so a quoted
/// parameter may hold a semicolon.
pub fn boundary_param(value: &[u8]) -> Option<String> {
    let mut pos = 0;
    while pos < value.len() {
        // A comment is CFWS, so a `;` inside one is text, not a separator.
        while pos < value.len() && value[pos] != b';' {
            if value[pos] == b'(' {
                if !skip_comment(&mut pos, value) {
                    return None;
                }
            } else {
                pos += 1;
            }
        }
        if pos >= value.len() {
            return None;
        }
        pos += 1;
        if !skip_cfws(&mut pos, value) {
            return None;
        }
        let name_start = pos;
        while pos < value.len() && is_token(value[pos]) {
            pos += 1;
        }
        let name = &value[name_start..pos];
        if !skip_cfws(&mut pos, value) {
            return None;
        }
        if pos >= value.len() || value[pos] != b'=' {
            continue;
        }
        pos += 1;
        if !skip_cfws(&mut pos, value) {
            return None;
        }
        let param = if pos < value.len() && value[pos] == b'"' {
            quoted(&mut pos, value)
        } else {
            let start = pos;
            while pos < value.len() && is_token(value[pos]) {
                pos += 1;
            }
            String::from_utf8(value[start..pos].to_vec()).ok()
        };
        if name.eq_ignore_ascii_case(b"boundary") {
            // An empty value names no boundary, so keep reading: a later
            // `boundary=` may be the one the sender meant.
            if let Some(param) = param {
                if !param.is_empty() {
                    return Some(param);
                }
            }
        }
    }
    None
}

fn skip_cfws(pos: &mut usize, value: &[u8]) -> bool {
    loop {
        while *pos < value.len() && is_wsp(value[*pos]) {
            *pos += 1;
        }
        if value.get(*pos) != Some(&b'(') {
            return true;
        }
        if !skip_comment(pos, value) {
            return false;
        }
    }
}

/// Skip one comment at `pos`, nested and with backslash quoted-pairs. Returns
/// false when it never closes.
fn skip_comment(pos: &mut usize, value: &[u8]) -> bool {
    let mut depth = 0usize;
    while *pos < value.len() {
        match value[*pos] {
            b'\\' => *pos += 2,
            b'(' => {
                depth += 1;
                *pos += 1;
            }
            b')' => {
                depth -= 1;
                *pos += 1;
                if depth == 0 {
                    return true;
                }
            }
            _ => *pos += 1,
        }
    }
    false
}

/// The body of the part that starts at `start`, ending before the line ending
/// that introduces the delimiter at `delimiter`.
fn part_end(body: &[u8], start: usize, delimiter: usize) -> Result<usize, Malformed> {
    if delimiter <= start {
        return Err(Malformed::new("empty MIME part"));
    }
    let mut end = delimiter;
    if end >= start + 2 && &body[end - 2..end] == b"\r\n" {
        end -= 2;
    } else if matches!(body[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    if end <= start {
        return Err(Malformed::new("empty MIME part"));
    }
    Ok(end)
}

fn is_delimiter(line: &[u8], delimiter: &str) -> bool {
    let mut text = line;
    while matches!(text.last(), Some(b' ' | b'\t')) {
        text = &text[..text.len() - 1];
    }
    text == delimiter.as_bytes()
}

fn valid_boundary(boundary: &str) -> bool {
    let bytes = boundary.as_bytes();
    (1..=70).contains(&bytes.len())
        && bytes.iter().all(|byte| is_bchar(*byte))
        && bytes.last() != Some(&b' ')
}

fn is_bchar(byte: u8) -> bool {
    byte == b' '
        || byte == b'\''
        || byte == b'('
        || byte == b')'
        || byte == b'+'
        || byte == b'_'
        || byte == b','
        || byte == b'-'
        || byte == b'.'
        || byte == b'/'
        || byte == b':'
        || byte == b'='
        || byte == b'?'
        || byte.is_ascii_alphanumeric()
}

fn is_wsp(byte: u8) -> bool {
    // A folded Content-Type puts CRLF between parameters.
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_graphic()
        && !matches!(
            byte,
            b'(' | b')'
                | b'<'
                | b'>'
                | b'@'
                | b','
                | b';'
                | b':'
                | b'\\'
                | b'"'
                | b'/'
                | b'['
                | b']'
                | b'?'
                | b'='
        )
}

fn quoted(pos: &mut usize, value: &[u8]) -> Option<String> {
    *pos += 1;
    let mut out = Vec::new();
    while *pos < value.len() {
        let byte = value[*pos];
        *pos += 1;
        match byte {
            b'"' => return String::from_utf8(out).ok(),
            b'\\' => {
                if *pos < value.len() {
                    out.push(value[*pos]);
                    *pos += 1;
                }
            }
            byte => out.push(byte),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::header::headers;

    const REPORT: &[u8] = b"Content-Type: multipart/report; report-type=delivery-status;\r\n\
        \tboundary=\"b1\"\r\n\
        \r\n\
        This is a preamble.\r\n\
        --b1\r\n\
        Content-Type: text/plain\r\n\
        \r\n\
        --b1 is not a boundary here\r\n\
        Content-Type: message/delivery-status\r\n\
        \r\n\
        Action: failed\r\n\
        Status: 5.1.1\r\n\
        --b1\r\n\
        Content-Type: message/delivery-status\r\n\
        \r\n\
        Reporting-MTA: dns; mail.example\r\n\
        \r\n\
        Action: failed\r\n\
        Status: 5.1.1\r\n\
        --b1--\r\n\
        epilogue\r\n";

    #[test]
    fn a_boundary_shaped_line_inside_text_plain_is_not_a_part() {
        let multipart = walk_multipart(REPORT, "b1").expect("walks");
        assert_eq!(multipart.parts.len(), 2);
        let first = String::from_utf8_lossy(multipart.parts[0].body);
        // The #908 shape: a whole DSN header block and a permanent failure are
        // inside the text part, and the walk must not promote them to a part.
        assert!(
            first.contains("Content-Type: message/delivery-status"),
            "{first}"
        );
        assert!(first.contains("Action: failed"), "{first}");
        assert!(first.contains("Status: 5.1.1"), "{first}");
        let second = String::from_utf8_lossy(multipart.parts[1].body);
        assert!(
            second.contains("Reporting-MTA: dns; mail.example"),
            "{second}"
        );
        assert!(!second.contains("is not a boundary here"), "{second}");
        assert_eq!(multipart.epilogue, b"epilogue\r\n");
    }

    #[test]
    fn a_boundary_prefix_is_not_the_boundary() {
        let body = b"--b1\r\nContent-Type: text/plain\r\n\r\n--b1x\r\n--b1-not\r\n--b1--\r\n";
        let multipart = walk_multipart(body, "b1").expect("walks");
        assert_eq!(multipart.parts.len(), 1);
        // The line ending before the closing delimiter belongs to the boundary.
        assert_eq!(multipart.parts[0].body, b"--b1x\r\n--b1-not");
        assert_eq!(
            multipart.parts[0].body_with_ending,
            b"--b1x\r\n--b1-not\r\n"
        );
    }

    #[test]
    fn transport_padding_and_lf_endings_are_accepted() {
        let body = b"--b1 \nContent-Type: text/plain\n\none\n--b1\t\nContent-Type: text/plain\n\ntwo\n--b1-- \n";
        let multipart = walk_multipart(body, "b1").expect("walks");
        assert_eq!(multipart.parts.len(), 2);
        assert_eq!(multipart.parts[0].body, b"one");
        assert_eq!(multipart.parts[1].body, b"two");
    }

    #[test]
    fn a_nested_multipart_walks_from_its_own_boundary() {
        let body = b"--outer\r\n\
            Content-Type: multipart/alternative; boundary=\"inner\"\r\n\
            \r\n\
            --inner\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            plain\r\n\
            --inner\r\n\
            Content-Type: text/html\r\n\
            \r\n\
            <p>html</p>\r\n\
            --inner--\r\n\
            --outer--\r\n";
        let outer = walk_multipart(body, "outer").expect("walks");
        assert_eq!(outer.parts.len(), 1);
        let part = outer.parts[0];
        let header = headers(part.headers)
            .into_iter()
            .find(|header| header.is("content-type"))
            .expect("a Content-Type header");
        let boundary = boundary_param(header.value(part.headers)).expect("boundary");
        assert_eq!(boundary, "inner");
        let inner = walk_multipart(part.body, &boundary).expect("walks");
        assert_eq!(inner.parts.len(), 2);
        assert_eq!(inner.parts[0].body, b"plain");
    }

    #[test]
    fn a_body_with_millions_of_delimiter_lines_is_refused_before_it_grows() {
        // A 35 MB save of `--b` lines used to collect millions of parts. The
        // cap stops at the 1025th, so the walk stays small and quick.
        let mut body = Vec::new();
        for _ in 0..50_000 {
            body.extend_from_slice(b"--b\r\nX: y\r\n\r\nbody\r\n");
        }
        body.extend_from_slice(b"--b--\r\n");
        let started = std::time::Instant::now();
        let error = walk_multipart(&body, "b").unwrap_err();
        assert_eq!(error.reason(), "too many MIME parts");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the cap must stop the walk before it reads the whole body"
        );
    }

    #[test]
    fn exactly_the_part_cap_is_accepted() {
        let mut body = Vec::new();
        for _ in 0..MAX_PARTS {
            body.extend_from_slice(b"--b\r\nX: y\r\n\r\nbody\r\n");
        }
        body.extend_from_slice(b"--b--\r\n");
        assert_eq!(
            walk_multipart(&body, "b").expect("walks").parts.len(),
            MAX_PARTS
        );
    }

    #[test]
    fn a_missing_or_premature_close_is_refused() {
        assert!(walk_multipart(b"--b1\r\nContent-Type: text/plain\r\n\r\nbody\r\n", "b1").is_err());
        assert!(walk_multipart(b"--b1--\r\n", "b1").is_err());
        assert!(walk_multipart(b"no delimiter\r\n", "b1").is_err());
    }

    #[test]
    fn a_boundary_outside_the_rfc_2046_alphabet_is_refused() {
        for boundary in ["", "has space at end ", "has*symbol", "has\nnewline"] {
            assert!(!valid_boundary(boundary), "{boundary}");
            assert!(walk_multipart(b"--b\r\n\r\n\r\n--b--\r\n", boundary).is_err());
        }
        for boundary in [
            "a",
            "a b",
            "--x",
            "kyriakon-1-abc",
            "a+b_c,d-e.f/g:h=i?j'k(l)m",
        ] {
            assert!(valid_boundary(boundary), "{boundary}");
        }
    }

    #[test]
    fn a_quoted_parameter_may_hold_a_semicolon() {
        assert_eq!(
            boundary_param(b"multipart/mixed; charset=\"x;y\"; boundary=\"a;b\""),
            Some("a;b".to_string())
        );
        assert_eq!(boundary_param(b"text/plain; charset=utf-8"), None);
        assert_eq!(
            boundary_param(b"multipart/mixed; BOUNDARY=abc"),
            Some("abc".to_string())
        );
        assert_eq!(
            boundary_param(b"multipart/mixed (; boundary=evil); boundary=real"),
            Some("real".to_string())
        );
        assert_eq!(
            boundary_param(b"multipart/mixed; (a (nested) comment) boundary=real"),
            Some("real".to_string())
        );
        assert_eq!(
            boundary_param(b"multipart/mixed; boundary=; boundary=b1"),
            Some("b1".to_string())
        );
        assert_eq!(
            boundary_param(b"multipart/mixed; boundary=\"\"; boundary=b1"),
            Some("b1".to_string())
        );
    }
}
