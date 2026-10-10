//! The shared question list: `openbsd/etc/onboard/questions.tsv`, installed to
//! `/var/db/onboard/questions.tsv`. One tab-separated record per line, one
//! question each, header `id prompt type branch required validation`.
//!
//! The file is the only place the question list exists. This module parses it
//! and says which questions a given branch shows; it does not restate a prompt
//! and it does not hold the answer options, because the fixed format has no
//! column for them (see `options` below for where the choices do live).


/// An answer type. The tokens are the file's, and the spelling is fixed by the
/// three front-ends sharing the file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Text,
    Choice,
    YesNo,
    Multiline,
    Addresses,
    Key,
    Acceptance,
}

impl Kind {
    pub fn token(self) -> &'static str {
        match self {
            Kind::Text => "text",
            Kind::Choice => "choice",
            Kind::YesNo => "yesno",
            Kind::Multiline => "multiline",
            Kind::Addresses => "addresses",
            Kind::Key => "key",
            Kind::Acceptance => "acceptance",
        }
    }

    fn parse(s: &str) -> Result<Kind, String> {
        Ok(match s {
            "text" => Kind::Text,
            "choice" => Kind::Choice,
            "yesno" => Kind::YesNo,
            "multiline" => Kind::Multiline,
            "addresses" => Kind::Addresses,
            "key" => Kind::Key,
            "acceptance" => Kind::Acceptance,
            other => return Err(format!("unknown answer type {other:?}")),
        })
    }
}

/// The branch a question belongs to. `Monastic` is not the person-or-body
/// answer: it is the monastic path, which the `orders` answer selects, so a
/// monastic question is shown on the person and monastic paths alike and its
/// requirement is settled when the form is submitted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Branch {
    All,
    Person,
    Body,
    Monastic,
}

impl Branch {
    fn parse(s: &str) -> Result<Branch, String> {
        Ok(match s {
            "all" => Branch::All,
            "person" => Branch::Person,
            "body" => Branch::Body,
            "monastic" => Branch::Monastic,
            other => return Err(format!("unknown branch {other:?}")),
        })
    }
}

/// One answer a `choice` question offers, with the label shown for it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Choice {
    pub value: String,
    pub label: String,
}

/// A validation rule, named rather than expressed, so all three front-ends
/// implement the same names. A `choice` question's answers are its validation,
/// so the options live in the rule: `choice:<value>=<label>|<value>=<label>`,
/// which keeps the file the only place the list exists.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Rule {
    None,
    Username,
    Address,
    MailKey,
    UploadKey,
    Choice(Vec<Choice>),
    MaxLen(usize),
}

impl Rule {
    fn parse(s: &str) -> Result<Rule, String> {
        Ok(match s {
            "none" => Rule::None,
            "username" => Rule::Username,
            "address" => Rule::Address,
            "mail-key" => Rule::MailKey,
            "upload-key" => Rule::UploadKey,
            other => match other.strip_prefix("choice:") {
                Some(list) => Rule::Choice(parse_choices(list)?),
                None => match other.strip_prefix("maxlen:") {
                    Some(n) => Rule::MaxLen(
                        n.parse()
                            .map_err(|_| format!("maxlen needs a number, got {n:?}"))?,
                    ),
                    None => return Err(format!("unknown validation {other:?}")),
                },
            },
        })
    }
}

/// The answers a `choice` question accepts. A question with none is refused
/// here, as a build error, rather than becoming a control with nothing in it.
fn parse_choices(list: &str) -> Result<Vec<Choice>, String> {
    let mut out = Vec::new();
    for pair in list.split('|') {
        let (value, label) = pair
            .split_once('=')
            .ok_or_else(|| format!("choice option {pair:?} is not value=label"))?;
        if value.is_empty() || label.is_empty() {
            return Err(format!("choice option {pair:?} has an empty value or label"));
        }
        out.push(Choice {
            value: value.to_string(),
            label: label.to_string(),
        });
    }
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct Question {
    pub id: String,
    pub prompt: String,
    pub kind: Kind,
    pub branch: Branch,
    pub required: bool,
    pub rule: Rule,
}

pub const HEADER: &str = "id\tprompt\ttype\tbranch\trequired\tvalidation";

/// Parse the file. A malformed line names itself rather than being skipped: a
/// question that disappears silently is a question no front-end asks.
pub fn parse(text: &str) -> Result<Vec<Question>, String> {
    let mut lines = text.lines();
    let header = lines
        .find(|l| !l.trim().is_empty())
        .ok_or("the question list is empty")?;
    if header.trim_end() != HEADER {
        return Err(format!(
            "the question list's header is {header:?}, expected {HEADER:?}"
        ));
    }

    let mut out = Vec::new();
    for (i, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 6 {
            return Err(format!(
                "question line {} has {} fields, expected 6",
                i + 2,
                f.len()
            ));
        }
        let required = match f[4] {
            "yes" => true,
            "no" => false,
            other => return Err(format!("line {}: required is {other:?}", i + 2)),
        };
        out.push(Question {
            id: f[0].to_string(),
            prompt: f[1].to_string(),
            kind: Kind::parse(f[2]).map_err(|e| format!("line {}: {e}", i + 2))?,
            branch: Branch::parse(f[3]).map_err(|e| format!("line {}: {e}", i + 2))?,
            required,
            rule: Rule::parse(f[5]).map_err(|e| format!("line {}: {e}", i + 2))?,
        });
    }
    Ok(out)
}

/// The questions a branch shows, in file order. `person` and `body` are the
/// person-or-body answer; monastic questions show on both, because the monastic
/// path is not known until the `orders` answer arrives.
pub fn shown(list: &[Question], person: bool) -> Vec<&Question> {
    list.iter()
        .filter(|q| match q.branch {
            Branch::All | Branch::Monastic => true,
            Branch::Person => person,
            Branch::Body => !person,
        })
        .collect()
}

/// Whether an answer selects the monastic path: the monastic answer to `orders`
/// makes the elder's or confessor's blessing required.
pub fn is_monastic(orders: Option<&str>) -> bool {
    matches!(orders, Some("monk") | Some("nun"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "id\tprompt\ttype\tbranch\trequired\tvalidation\n\
username\tUsername\ttext\tall\tyes\tusername\n\
whose\tIs this for you, or for a body?\tchoice\tall\tyes\tchoice:person=Just me|body=A body\n\
body_name\tThe body's name\ttext\tbody\tyes\tnone\n\
mail_key\tYour public key\tkey\tperson\tyes\tmail-key\n\
blessing\tBlessing?\tmultiline\tmonastic\tyes\tnone\n";

    #[test]
    fn parses_and_filters_by_branch() {
        let list = parse(SAMPLE).unwrap();
        assert_eq!(list.len(), 5);
        assert_eq!(list[0].kind, Kind::Text);
        assert_eq!(list[1].branch, Branch::All);
        assert!(list[0].required);
        assert_eq!(list[4].rule, Rule::None);

        let person: Vec<&str> = shown(&list, true).iter().map(|q| q.id.as_str()).collect();
        assert_eq!(person, ["username", "whose", "mail_key", "blessing"]);
        let body: Vec<&str> = shown(&list, false).iter().map(|q| q.id.as_str()).collect();
        assert_eq!(body, ["username", "whose", "body_name", "blessing"]);
    }

    #[test]
    fn a_malformed_line_is_named_not_skipped() {
        let bad = "id\tprompt\ttype\tbranch\trequired\tvalidation\npassword\tPassword\ttext\tall\tyes\n";
        let e = parse(bad).unwrap_err();
        assert!(e.contains("line 2"), "{e}");

        let unknown = "id\tprompt\ttype\tbranch\trequired\tvalidation\nx\tX\ttext\tall\tyes\tnope\n";
        assert!(parse(unknown).unwrap_err().contains("nope"));
    }

    #[test]
    fn maxlen_carries_its_number() {
        let t = "id\tprompt\ttype\tbranch\trequired\tvalidation\nx\tX\ttext\tall\tno\tmaxlen:12\n";
        assert_eq!(parse(t).unwrap()[0].rule, Rule::MaxLen(12));
    }

    #[test]
    fn the_monastic_answer_selects_the_monastic_path() {
        assert!(is_monastic(Some("monk")));
        assert!(is_monastic(Some("nun")));
        assert!(!is_monastic(Some("layman")));
        assert!(!is_monastic(None));
    }

    #[test]
    fn a_choice_carries_its_options_in_the_rule() {
        let list = parse(SAMPLE).unwrap();
        match &list[1].rule {
            Rule::Choice(opts) => {
                assert_eq!(opts.len(), 2);
                assert_eq!(opts[0].value, "person");
                assert_eq!(opts[0].label, "Just me");
                assert_eq!(opts[1].value, "body");
                assert_eq!(opts[1].label, "A body");
            }
            other => panic!("whose is not a choice: {other:?}"),
        }
    }

    #[test]
    fn a_label_may_hold_a_comma_and_a_colon() {
        let t = "id\tprompt\ttype\tbranch\trequired\tvalidation\nx\tX\tchoice\tall\tyes\tchoice:card=Card, £20 a year|none=No charge: anyone who cannot pay\n";
        match &parse(t).unwrap()[0].rule {
            Rule::Choice(opts) => {
                assert_eq!(opts[0].label, "Card, £20 a year");
                assert_eq!(opts[1].label, "No charge: anyone who cannot pay");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_choice_with_no_options_is_a_build_error() {
        let bare = "id\tprompt\ttype\tbranch\trequired\tvalidation\nx\tX\tchoice\tall\tyes\tchoice\n";
        let e = parse(bare).unwrap_err();
        assert!(e.contains("unknown validation"), "{e}");

        let empty = "id\tprompt\ttype\tbranch\trequired\tvalidation\nx\tX\tchoice\tall\tyes\tchoice:\n";
        let e = parse(empty).unwrap_err();
        assert!(e.contains("value=label"), "{e}");
    }

    #[test]
    fn a_malformed_option_is_named() {
        let t = "id\tprompt\ttype\tbranch\trequired\tvalidation\nx\tX\tchoice\tall\tyes\tchoice:noequals\n";
        assert!(parse(t).unwrap_err().contains("value=label"));
        let t = "id\tprompt\ttype\tbranch\trequired\tvalidation\nx\tX\tchoice\tall\tyes\tchoice:=nolabel\n";
        assert!(parse(t).unwrap_err().contains("empty value or label"));
    }
}
