//! One-pass RFC 5322 mailbox-list parsing.
//!
//! The grammar follows OpenBSD `filter-dkimsign`'s `mheader.c`, because the
//! signer and the From check must read the same header the same way: obsolete
//! whitespace before the colon, nested comments, backslash quoted-pairs, quoted
//! strings, and a mailbox list are all part of that grammar. Parsing is one
//! cursor over the value with no rescans, so time and memory are linear in the
//! header's length.

use crate::Malformed;

/// A comment nested deeper than this is refused rather than walked. The parse
/// is iterative, so this is a sanity bound, not a stack guard.
const MAX_COMMENT_DEPTH: usize = 64;

/// One mailbox from an address list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mailbox {
    /// The addr-spec with comments and folding whitespace removed. Quoted
    /// strings keep their quotes and escapes.
    pub address: String,
    /// The domain after the `@`, lowercased only by the caller's comparison.
    /// `None` for a bare localpart, which cron and mail(1) write and which the
    /// local enqueuer accepts.
    pub domain: Option<String>,
}

/// Parse a header value as an RFC 5322 address list.
///
/// Every mailbox is returned in order. A header the grammar cannot read is an
/// error rather than a shorter list: a caller that checks sender addresses must
/// see the whole header or refuse the message.
pub fn parse_address_list(value: &[u8]) -> Result<Vec<Mailbox>, Malformed> {
    let mut parser = Parser::new(value);
    parser.skip_cfws()?;
    // Obs mailbox-list permits a run of commas before the first mailbox; the
    // signer skips them and reads the first mailbox after them.
    while parser.eat(b',') {
        parser.skip_cfws()?;
    }
    if parser.at_end() {
        return Ok(Vec::new());
    }

    let mut mailboxes = Vec::new();
    loop {
        mailboxes.push(parser.mailbox()?);
        parser.skip_cfws()?;
        if parser.at_end() {
            return Ok(mailboxes);
        }
        if !parser.eat(b',') {
            return Err(Malformed::new("text after the address list"));
        }
        parser.skip_cfws()?;
        if parser.at_end() {
            return Err(Malformed::new("address list ends with a comma"));
        }
    }
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn skip_wsp(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }

    fn skip_cfws(&mut self) -> Result<(), Malformed> {
        loop {
            self.skip_wsp();
            if self.peek() == Some(b'(') {
                self.skip_comment()?;
            } else {
                return Ok(());
            }
        }
    }

    fn skip_comment(&mut self) -> Result<(), Malformed> {
        debug_assert_eq!(self.peek(), Some(b'('));
        self.pos += 1;
        let mut depth = 1;
        while depth > 0 {
            match self.peek() {
                None => return Err(Malformed::new("unterminated comment")),
                Some(b'\\') => {
                    self.pos += 1;
                    if self.peek().is_none() {
                        return Err(Malformed::new("unterminated comment"));
                    }
                    self.pos += 1;
                }
                Some(b'(') => {
                    depth += 1;
                    if depth > MAX_COMMENT_DEPTH {
                        return Err(Malformed::new("comment nested too deeply"));
                    }
                    self.pos += 1;
                }
                Some(b')') => {
                    depth -= 1;
                    self.pos += 1;
                }
                Some(_) => self.pos += 1,
            }
        }
        Ok(())
    }

    fn skip_quoted(&mut self) -> Result<(), Malformed> {
        debug_assert_eq!(self.peek(), Some(b'"'));
        self.pos += 1;
        loop {
            match self.peek() {
                None => return Err(Malformed::new("unterminated quoted string")),
                Some(b'\\') => {
                    self.pos += 1;
                    if self.peek().is_none() {
                        return Err(Malformed::new("unterminated quoted string"));
                    }
                    self.pos += 1;
                }
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    fn skip_atext(&mut self) -> bool {
        if self.peek().is_some_and(is_atext) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn skip_dot_atom_text(&mut self) -> bool {
        if !self.skip_atext() {
            return false;
        }
        loop {
            while self.skip_atext() {}
            if !self.eat(b'.') {
                return true;
            }
        }
    }

    fn skip_atom(&mut self) -> Result<bool, Malformed> {
        let save = self.pos;
        self.skip_cfws()?;
        if !self.skip_atext() {
            self.pos = save;
            return Ok(false);
        }
        while self.skip_atext() {}
        self.skip_cfws()?;
        Ok(true)
    }

    fn skip_dot_atom(&mut self) -> Result<bool, Malformed> {
        let save = self.pos;
        self.skip_cfws()?;
        if !self.skip_dot_atom_text() {
            self.pos = save;
            return Ok(false);
        }
        self.skip_cfws()?;
        Ok(true)
    }

    fn skip_quoted_string(&mut self) -> Result<bool, Malformed> {
        let save = self.pos;
        self.skip_cfws()?;
        if self.peek() != Some(b'"') {
            self.pos = save;
            return Ok(false);
        }
        self.skip_quoted()?;
        self.skip_cfws()?;
        Ok(true)
    }

    fn skip_word(&mut self) -> Result<bool, Malformed> {
        if self.skip_atom()? {
            return Ok(true);
        }
        self.skip_quoted_string()
    }

    fn skip_phrase(&mut self) -> Result<bool, Malformed> {
        let save = self.pos;
        if !self.skip_word()? {
            self.pos = save;
            return Ok(false);
        }
        loop {
            if self.skip_word()? {
                continue;
            }
            if self.eat(b'.') {
                continue;
            }
            let before = self.pos;
            self.skip_cfws()?;
            if self.pos == before {
                return Ok(true);
            }
        }
    }

    fn skip_local_part(&mut self) -> Result<bool, Malformed> {
        let save = self.pos;
        if self.skip_dot_atom()? {
            return Ok(true);
        }
        self.pos = save;
        if self.skip_quoted_string()? {
            return Ok(true);
        }
        self.pos = save;
        // obs-local-part: word *("." word)
        if !self.skip_word()? {
            self.pos = save;
            return Ok(false);
        }
        loop {
            let dot = self.pos;
            if !self.eat(b'.') {
                return Ok(true);
            }
            if !self.skip_word()? {
                self.pos = dot;
                return Ok(true);
            }
        }
    }

    fn skip_domain_literal(&mut self) -> Result<bool, Malformed> {
        let save = self.pos;
        self.skip_cfws()?;
        if !self.eat(b'[') {
            self.pos = save;
            return Ok(false);
        }
        loop {
            self.skip_wsp();
            match self.peek() {
                None => return Err(Malformed::new("unterminated domain literal")),
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                Some(b'\\') => {
                    self.pos += 1;
                    if self.peek().is_none() {
                        return Err(Malformed::new("unterminated domain literal"));
                    }
                    self.pos += 1;
                }
                Some(_) => self.pos += 1,
            }
        }
        self.skip_cfws()?;
        Ok(true)
    }

    fn skip_domain(&mut self) -> Result<bool, Malformed> {
        let save = self.pos;
        if self.skip_dot_atom()? {
            return Ok(true);
        }
        self.pos = save;
        if self.skip_domain_literal()? {
            return Ok(true);
        }
        self.pos = save;
        // obs-domain: atom *("." atom)
        if !self.skip_atom()? {
            self.pos = save;
            return Ok(false);
        }
        while self.peek() == Some(b'.') {
            let dot = self.pos;
            self.pos += 1;
            if !self.skip_atom()? {
                self.pos = dot;
                break;
            }
        }
        Ok(true)
    }

    fn skip_addr_spec(&mut self) -> Result<Option<Mailbox>, Malformed> {
        let start = self.pos;
        if !self.skip_local_part()? {
            self.pos = start;
            return Ok(None);
        }
        let local_end = self.pos;
        self.skip_cfws()?;
        if !self.eat(b'@') {
            self.pos = start;
            return Ok(None);
        }
        let domain_start = self.pos;
        if !self.skip_domain()? {
            self.pos = start;
            return Ok(None);
        }
        let domain_end = self.pos;
        let local = normalize(&self.input[start..local_end]);
        let domain = normalize(&self.input[domain_start..domain_end]);
        if local.is_empty() || domain.is_empty() {
            self.pos = start;
            return Ok(None);
        }
        Ok(Some(Mailbox {
            address: format!("{local}@{domain}"),
            domain: Some(domain),
        }))
    }

    fn skip_obs_route(&mut self) -> Result<bool, Malformed> {
        let start = self.pos;
        self.skip_cfws()?;
        if !self.eat(b'@') {
            self.pos = start;
            return Ok(false);
        }
        if !self.skip_domain()? {
            self.pos = start;
            return Ok(false);
        }
        loop {
            let before_comma = self.pos;
            self.skip_cfws()?;
            if !self.eat(b',') {
                self.pos = before_comma;
                break;
            }
            self.skip_cfws()?;
            if !self.eat(b'@') || !self.skip_domain()? {
                self.pos = start;
                return Ok(false);
            }
        }
        if !self.eat(b':') {
            self.pos = start;
            return Ok(false);
        }
        Ok(true)
    }

    fn skip_angle_addr(&mut self) -> Result<Option<Mailbox>, Malformed> {
        let start = self.pos;
        self.skip_cfws()?;
        if !self.eat(b'<') {
            self.pos = start;
            return Ok(None);
        }
        let addr = match self.skip_addr_spec()? {
            Some(addr) => Some(addr),
            None if self.skip_obs_route()? => self.skip_addr_spec()?,
            None => None,
        };
        self.skip_cfws()?;
        let Some(addr) = addr else {
            self.pos = start;
            return Ok(None);
        };
        if !self.eat(b'>') {
            self.pos = start;
            return Ok(None);
        }
        self.skip_cfws()?;
        Ok(Some(addr))
    }

    fn skip_name_addr(&mut self) -> Result<Option<Mailbox>, Malformed> {
        let start = self.pos;
        self.skip_cfws()?;
        self.skip_phrase()?;
        self.skip_cfws()?;
        if let Some(addr) = self.skip_angle_addr()? {
            return Ok(Some(addr));
        }
        self.pos = start;
        Ok(None)
    }

    fn skip_bare_local(&mut self) -> Result<Option<Mailbox>, Malformed> {
        let start = self.pos;
        if !self.skip_local_part()? {
            self.pos = start;
            return Ok(None);
        }
        let address = normalize(&self.input[start..self.pos]);
        if address.is_empty() {
            self.pos = start;
            return Ok(None);
        }
        Ok(Some(Mailbox {
            address,
            domain: None,
        }))
    }

    fn mailbox(&mut self) -> Result<Mailbox, Malformed> {
        let start = self.pos;
        if let Some(mailbox) = self.skip_name_addr()? {
            return Ok(mailbox);
        }
        self.pos = start;
        if let Some(mailbox) = self.skip_addr_spec()? {
            return Ok(mailbox);
        }
        self.pos = start;
        if let Some(mailbox) = self.skip_bare_local()? {
            return Ok(mailbox);
        }
        self.pos = start;
        Err(Malformed::new("not a mailbox"))
    }
}

fn is_atext(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

/// Remove CFWS from a parsed slice, keeping quoted strings byte for byte.
fn normalize(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut pos = 0;
    while pos < raw.len() {
        match raw[pos] {
            b'(' => {
                let mut depth = 0usize;
                while pos < raw.len() {
                    match raw[pos] {
                        b'\\' => pos += 2,
                        b'(' => {
                            depth += 1;
                            pos += 1;
                        }
                        b')' => {
                            depth -= 1;
                            pos += 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => pos += 1,
                    }
                }
            }
            b'"' => {
                out.push(b'"');
                pos += 1;
                while pos < raw.len() {
                    let byte = raw[pos];
                    out.push(byte);
                    pos += 1;
                    if byte == b'\\' && pos < raw.len() {
                        out.push(raw[pos]);
                        pos += 1;
                    } else if byte == b'"' {
                        break;
                    }
                }
            }
            b' ' | b'\t' | b'\r' | b'\n' => pos += 1,
            byte => {
                out.push(byte);
                pos += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{headers, split_message};

    fn addresses(value: &[u8]) -> Vec<String> {
        parse_address_list(value)
            .expect("parses")
            .into_iter()
            .map(|mailbox| mailbox.address)
            .collect()
    }

    #[test]
    fn one_mailbox_with_display_name_and_comments() {
        let parsed =
            parse_address_list(b"Alice (the platform) <alice@example.invalid> (a comment)")
                .expect("parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].address, "alice@example.invalid");
        assert_eq!(parsed[0].domain.as_deref(), Some("example.invalid"));
    }

    #[test]
    fn multiple_mailboxes_are_returned_in_order() {
        assert_eq!(
            addresses(b"alice@example.invalid, Bob <bob@example.invalid>"),
            vec!["alice@example.invalid", "bob@example.invalid"]
        );
        assert_eq!(
            addresses(b"<alice@example.invalid>, bob@example.invalid, carol@example.invalid"),
            vec![
                "alice@example.invalid",
                "bob@example.invalid",
                "carol@example.invalid"
            ]
        );
        assert_eq!(
            parse_address_list(b"alice@example.invalid, bob@example.invalid")
                .expect("parses")
                .len(),
            2
        );
    }

    #[test]
    fn a_quoted_string_is_not_a_comment() {
        assert_eq!(
            addresses(b"\"x(\" <secretary@otherparish.org>, \"y)\" <alice@kyriakon.net>"),
            vec!["secretary@otherparish.org", "alice@kyriakon.net"]
        );
        assert_eq!(
            addresses(b"\"A, Inc.\" <alice@example.invalid>"),
            vec!["alice@example.invalid"]
        );
        assert_eq!(
            addresses(b"\"Alice \\\"Q\\\" Public, Inc.\" <alice@example.invalid>"),
            vec!["alice@example.invalid"]
        );
    }

    #[test]
    fn a_comment_may_nest_and_escape_a_paren() {
        assert_eq!(
            addresses(b"alice(one(two)three)@(x)example.invalid"),
            vec!["alice@example.invalid"]
        );
        assert_eq!(
            addresses(b"(a\\)b) alice@example.invalid"),
            vec!["alice@example.invalid"]
        );
    }

    #[test]
    fn the_escaped_paren_header_resolves_to_the_mailbox_the_signer_reads() {
        // #923: filter-fromcheck's comment stripping saw only alice; the RFC
        // parse and filter-dkimsign see only secretary.
        let value = b"(\\)\" )\"<alice@kyriakon.net>(\" <secretary@otherparish.org> (\\))";
        let parsed = parse_address_list(value).expect("parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].address, "secretary@otherparish.org");
    }

    #[test]
    fn the_obsolete_from_header_is_found_and_its_address_read() {
        // #923 bypass one: whitespace before the colon is a From to the signer.
        let msg = b"From : secretary@otherparish.org\r\n\
            From: alice@kyriakon.net\r\n\
            \r\n\
            body\r\n";
        let split = split_message(msg).expect("splits");
        let froms: Vec<_> = headers(split.headers)
            .into_iter()
            .filter(|header| header.is("from"))
            .collect();
        assert_eq!(froms.len(), 2);
        assert_eq!(
            addresses(froms[0].value(split.headers)),
            vec!["secretary@otherparish.org"]
        );
        assert_eq!(
            addresses(froms[1].value(split.headers)),
            vec!["alice@kyriakon.net"]
        );
    }

    #[test]
    fn a_large_folded_obsolete_from_header_is_one_pass() {
        // #894: a folded header may be megabytes, and the parse must not rescan
        // it per comment pair.
        let mut value = b"Alice".to_vec();
        for _ in 0..60_000 {
            value.extend_from_slice(b"\r\n\t(comment)");
        }
        value.extend_from_slice(b"\r\n\t <alice@example.invalid>");
        assert_eq!(addresses(&value), vec!["alice@example.invalid"]);
    }

    #[test]
    fn a_bare_localpart_is_a_mailbox_with_no_domain() {
        let parsed = parse_address_list(b"root (Cron Daemon)").expect("parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].address, "root");
        assert_eq!(parsed[0].domain, None);
    }

    #[test]
    fn a_header_the_grammar_cannot_read_is_refused() {
        for value in [
            b"alice@example.invalid (unterminated".as_slice(),
            b"\"unterminated <alice@example.invalid>",
            b"alice@example.invalid <bob@example.invalid>",
            b"Group: alice@example.invalid, bob@example.invalid;",
            b"alice@example.invalid,",
        ] {
            assert!(parse_address_list(value).is_err(), "{value:?}");
        }
    }
}
