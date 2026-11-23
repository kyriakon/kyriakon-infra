//! The line-ending rule, the header/body split, and the header spans.
//!
//! A line ends at LF, at CRLF, or at a bare CR. That one rule is [`lines`], and
//! [`split_message`] and [`headers`] are built from it, so the body always
//! starts after a line the span scan also sees as empty.

use crate::Malformed;

/// One line of a block, without its line ending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line<'a> {
    /// The line's bytes, with LF, CRLF, or the bare CR removed.
    pub text: &'a [u8],
    /// Offset of the first byte of the line.
    pub start: usize,
    /// Offset of the first byte after the line ending.
    pub next: usize,
}

impl<'a> Line<'a> {
    /// Offset just past the line's text, where its ending starts.
    pub fn end(&self) -> usize {
        self.start + self.text.len()
    }

    /// The line ending as the message wrote it: `\n`, `\r\n`, or `\r`.
    pub fn ending<'b>(&self, block: &'b [u8]) -> &'b [u8] {
        &block[self.end()..self.next]
    }
}

/// The lines of `block` under the strict line-ending rule.
pub fn lines(block: &[u8]) -> Lines<'_> {
    lines_from(block, 0)
}

pub(crate) fn lines_from(block: &[u8], pos: usize) -> Lines<'_> {
    Lines { block, pos }
}

/// Iterator over [`Line`]s. Yields nothing at or past the end of the block.
#[derive(Clone, Debug)]
pub struct Lines<'a> {
    block: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for Lines<'a> {
    type Item = Line<'a>;

    fn next(&mut self) -> Option<Line<'a>> {
        if self.pos >= self.block.len() {
            return None;
        }
        let start = self.pos;
        let (end, next) = match self.block[start..]
            .iter()
            .position(|&b| b == b'\n' || b == b'\r')
        {
            Some(off) => {
                let end = start + off;
                let next = if self.block[end] == b'\r' && self.block.get(end + 1) == Some(&b'\n') {
                    end + 2
                } else {
                    end + 1
                };
                (end, next)
            }
            None => (self.block.len(), self.block.len()),
        };
        self.pos = next;
        Some(Line {
            text: &self.block[start..end],
            start,
            next,
        })
    }
}

/// The three slices of a message: header block, the empty line that ends it,
/// and the body.
///
/// `separator` is empty when the message is all headers, which is the shape a
/// filter sees before any body line has arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message<'a> {
    /// Every header line including its folding, without the empty line.
    pub headers: &'a [u8],
    /// The empty line that ends the header block, with its line ending.
    pub separator: &'a [u8],
    /// Everything after the separator.
    pub body: &'a [u8],
}

/// Split an RFC 5322 message at its header/body boundary.
///
/// The split uses [`lines`], the same rule [`headers`] uses. A message with no
/// empty line whose header block is not all headers is refused rather than read
/// as one long header: a body line behind a separator this rule cannot see must
/// not be copied out of the ciphertext as an exposed header.
pub fn split_message(msg: &[u8]) -> Result<Message<'_>, Malformed> {
    for line in lines(msg) {
        if line.text.is_empty() {
            return Ok(Message {
                headers: &msg[..line.start],
                separator: &msg[line.start..line.next],
                body: &msg[line.next..],
            });
        }
    }
    if all_headers(msg) {
        Ok(Message {
            headers: msg,
            separator: b"",
            body: b"",
        })
    } else {
        Err(Malformed::new(
            "no empty line before content that is not a header",
        ))
    }
}

/// Whether every line is a header or a continuation of the header above it.
///
/// This is the same name/continuation split [`headers`] makes, so a block this
/// accepts yields no header the span scan would drop.
fn all_headers(block: &[u8]) -> bool {
    let mut open = false;
    for line in lines(block) {
        if is_continuation(line.text) {
            if !open {
                return false;
            }
        } else if name_of(line.text).is_some() {
            open = true;
        } else {
            return false;
        }
    }
    true
}

/// The span of one header in its block: its name, the byte range covering the
/// header and its folded continuation lines, and its value after the colon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    name: &'a [u8],
    start: usize,
    colon: usize,
    end: usize,
}

impl<'a> Header<'a> {
    /// The field name as written, with whitespace before the colon removed.
    ///
    /// Removing it is what lets an obsolete `From :` be recognised as a From
    /// header, as OpenBSD `filter-dkimsign` reads it.
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// Whether this header's name is `name`, case-insensitively.
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name.as_bytes())
    }

    /// Offset of the header's first byte.
    pub fn start(&self) -> usize {
        self.start
    }

    /// Offset just past the header's last continuation line, ending excluded.
    pub fn end(&self) -> usize {
        self.end
    }

    /// The header's value: bytes after the colon, folding included.
    pub fn value<'b>(&self, block: &'b [u8]) -> &'b [u8] {
        &block[self.colon + 1..self.end]
    }
}

/// Every header in a header block, in order.
///
/// A line beginning with a space or tab continues the header above it. A line
/// that is neither a header nor a continuation belongs to no span: callers copy
/// exposed spans out of the clear wrapper, so folding arbitrary text into a
/// header would put it outside the ciphertext.
pub fn headers(block: &[u8]) -> Vec<Header<'_>> {
    let mut spans: Vec<Header<'_>> = Vec::new();
    let mut open = false;
    for line in lines(block) {
        if is_continuation(line.text) {
            if open {
                if let Some(last) = spans.last_mut() {
                    last.end = line.end();
                }
            } else {
                open = false;
            }
            continue;
        }
        match name_of(line.text) {
            Some((name, colon)) => {
                spans.push(Header {
                    name,
                    start: line.start,
                    colon: line.start + colon,
                    end: line.end(),
                });
                open = true;
            }
            None => open = false,
        }
    }
    spans
}

fn is_continuation(line: &[u8]) -> bool {
    matches!(line.first(), Some(b' ' | b'\t'))
}

/// The name (whitespace before the colon removed) and colon offset of a header
/// line, or `None` when the line is not a header.
fn name_of(line: &[u8]) -> Option<(&[u8], usize)> {
    let colon = line.iter().position(|&b| b == b':')?;
    let mut end = colon;
    while end > 0 && matches!(line[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    Some((&line[..end], colon))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_cr_separates_the_body_from_the_headers() {
        let msg = b"From: a@b\rSubject: s\r\rFrom: SECRET-BODY-TEXT\r\n";
        let split = split_message(msg).expect("splits");
        // The header block keeps the ending of its last line; the separator is
        // the empty line itself.
        assert_eq!(split.headers, b"From: a@b\rSubject: s\r");
        assert_eq!(split.separator, b"\r");
        assert_eq!(split.body, b"From: SECRET-BODY-TEXT\r\n");

        let spans = headers(split.headers);
        assert_eq!(
            spans.iter().map(Header::name).collect::<Vec<_>>(),
            vec![b"From".as_slice(), b"Subject".as_slice()]
        );
        assert!(
            spans.iter().all(|h| h.end() <= split.headers.len()),
            "a span must stay in the header block"
        );
    }

    #[test]
    fn a_message_with_only_bare_cr_line_endings_splits_cleanly() {
        let msg = b"From: a@b\rSubject: s\r\rbody text\r";
        let split = split_message(msg).expect("splits");
        assert_eq!(split.body, b"body text\r");
        assert_eq!(headers(split.headers).len(), 2);
    }

    #[test]
    fn the_split_and_the_span_scan_share_the_line_rule() {
        for msg in [
            b"From: a@b\nSubject: s\n\nbody".as_slice(),
            b"From: a@b\r\nSubject: s\r\n\r\nbody",
            b"From: a@b\rSubject: s\r\rbody",
            b"From: a@b\nSubject: s\r\n\rbody",
        ] {
            let split = split_message(msg).expect("splits");
            for header in headers(split.headers) {
                assert!(header.end() <= split.headers.len());
                assert!(std::str::from_utf8(&split.headers[header.start()..header.end()]).is_ok());
            }
            assert!(split.body != split.headers);
        }
    }

    #[test]
    fn a_message_with_no_empty_line_is_headers_only_when_every_line_is_one() {
        assert!(split_message(b"From: a@b\rSubject: s\r").is_ok());
        assert!(split_message(b"not a header\rFrom: SECRET\r").is_err());
        assert!(split_message(b"From: a@b\n not a header\n").is_ok());
        assert!(split_message(b" no header above\n").is_err());
    }

    #[test]
    fn an_obsolete_from_with_space_before_the_colon_has_the_name_from() {
        let block = b"From : secretary@otherparish.org\r\nFrom:\talice@kyriakon.net\r\n";
        let spans = headers(block);
        assert_eq!(spans.len(), 2);
        assert!(spans[0].is("from"), "{:?}", spans[0].name());
        assert_eq!(spans[0].value(block), b" secretary@otherparish.org");
        assert!(spans[1].is("from"));
        assert_eq!(spans[1].value(block), b"\talice@kyriakon.net");
    }

    #[test]
    fn an_oversized_folded_header_stays_one_span() {
        let mut block = b"From: Alice".to_vec();
        for _ in 0..64_000 {
            block.extend_from_slice(b"\r\n\t(comment)");
        }
        block.extend_from_slice(b"\r\n\r\nbody\r\n");
        let split = split_message(&block).expect("splits");
        let spans = headers(split.headers);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].name(), b"From");
        // The span excludes the last line ending, which the block keeps.
        assert_eq!(spans[0].end() + 2, split.headers.len());
        assert!(split.headers.ends_with(b"\r\n"));
        assert_eq!(split.body, b"body\r\n");
    }

    #[test]
    fn a_clearsigned_block_in_the_body_keeps_its_headers_in_the_body() {
        let msg = b"From: alice@example.invalid\r\n\
            Subject: req -----BEGIN PGP SIGNED MESSAGE-----x\r\n\
            \r\n\
            -----BEGIN PGP SIGNED MESSAGE-----\r\n\
            Hash: SHA256\r\n\
            \r\n\
            From: mallory@example.invalid\r\n\
            please erase me\r\n\
            -----BEGIN PGP SIGNATURE-----\r\n\
            c2ln\r\n\
            -----END PGP SIGNATURE-----\r\n";
        let split = split_message(msg).expect("splits");
        assert_eq!(
            headers(split.headers).len(),
            2,
            "outer block: {}",
            String::from_utf8_lossy(split.headers)
        );
        assert!(
            !split.headers.windows(4).any(|window| window == b"Hash"),
            "the inner Hash header must not reach the outer block"
        );

        // The armour is body text, and reading it as its own message yields the
        // inner headers: nesting is a property of the body, not a second header
        // block to merge.
        let inner = split_message(split.body).expect("the armour splits");
        let inner_headers = headers(inner.headers);
        assert_eq!(inner_headers.len(), 1);
        assert!(inner_headers[0].is("Hash"));
        assert!(inner.body.starts_with(b"From: mallory@example.invalid"));
    }
}
