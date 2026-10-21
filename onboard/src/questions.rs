//! The shared question list: `onboard/questions.toml`, which the crate reads at
//! build time. One `[[question]]` array per question, in display order, which is
//! the order the front-ends render and ask.
//!
//! The file is the only place the list exists, and the crate is its only home: it
//! is not installed into the store and no config key names it, so the store holds
//! no copy to drift from. This module parses it and says which questions a given
//! branch shows; it does not restate a prompt and it does not hold an answer
//! option, because the options are the question's own `choices` list, which is
//! what a `choice` question's validation is.
//!
//! The structure ships with the service and the wording does not have to: the site
//! workstream owns the prompts and this file is how its text reaches the crate. A
//! wording change is therefore a rebuild rather than a deploy, which is the
//! accepted price of one home for the list.

use serde::Deserialize;

/// The tracked file this module parses, named in the refusals so a failure says
/// which file to look at rather than which function returned.
pub const TRACKED: &str = "onboard/questions.toml";

/// The question list the crate carries, read at build time. The file is compiled
/// into the binary, so no path is read at startup and no copy of it can differ
/// from the one the service was built with. A list that does not parse is a
/// service that will not start, and the check above is the build failing first.
pub fn shipped() -> Result<Vec<Question>, String> {
    parse(include_str!("../questions.toml"))
}

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

/// One answer a `choice` question offers, with the label shown for it. Written
/// in the file as `{ value = "person", label = "Just me" }`, so a value and the
/// words shown for it cannot be read as each other.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    pub value: String,
    pub label: String,
}

/// A validation rule, named rather than expressed, so all three front-ends
/// implement the same names. A `choice` question's answers are its validation,
/// so its rule is the question's own `choices` list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Rule {
    None,
    Username,
    Usernames,
    Address,
    Domain,
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
            "usernames" => Rule::Usernames,
            "address" => Rule::Address,
            "domain" => Rule::Domain,
            "mail-key" => Rule::MailKey,
            "upload-key" => Rule::UploadKey,
            other => match other.strip_prefix("maxlen:") {
                Some(n) => Rule::MaxLen(
                    n.parse()
                        .map_err(|_| format!("maxlen needs a number, got {n:?}"))?,
                ),
                None => return Err(format!("unknown validation {other:?}")),
            },
        })
    }
}

/// The file, as serde reads it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    /// The questions, in display order, which the array of tables preserves.
    #[serde(default)]
    question: Vec<Entry>,
}

/// One `[[question]]`, before its tokens are checked against their vocabularies.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    prompt: String,
    #[serde(rename = "type")]
    kind: String,
    branch: String,
    required: bool,
    /// A `choice` question's answers. Absent on every other question, and on a
    /// `yesno` in particular, where Yes and No are the type's own rendering.
    #[serde(default)]
    choices: Vec<Choice>,
    /// The named rule an answer must pass, absent when nothing but the answer
    /// type's own shape is required.
    #[serde(default)]
    validation: Option<String>,
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

/// Parse the file. A question that is malformed, or that names a token outside
/// its vocabulary, is refused by name rather than skipped: a question that
/// disappears silently is a question no front-end asks.
pub fn parse(text: &str) -> Result<Vec<Question>, String> {
    let file: File = toml::from_str(text).map_err(|e| format!("the question list: {e}"))?;

    let mut out = Vec::with_capacity(file.question.len());
    for e in file.question {
        let id = e.id;
        let kind = Kind::parse(&e.kind).map_err(|why| format!("the question {id:?}: {why}"))?;
        let branch =
            Branch::parse(&e.branch).map_err(|why| format!("the question {id:?}: {why}"))?;
        let rule = rule(&id, kind, e.choices, e.validation)?;
        out.push(Question {
            id,
            prompt: e.prompt,
            kind,
            branch,
            required: e.required,
            rule,
        });
    }
    Ok(out)
}

/// The rule a question's answer must pass. A `choice` question's is its choices,
/// and a question with none is refused here, as a build error, rather than
/// becoming a control with nothing in it.
fn rule(
    id: &str,
    kind: Kind,
    choices: Vec<Choice>,
    validation: Option<String>,
) -> Result<Rule, String> {
    if kind == Kind::Choice {
        if choices.is_empty() {
            return Err(format!("the question {id:?} is a choice with no choices"));
        }
        if validation.is_some() {
            return Err(format!(
                "the question {id:?} is a choice, so its validation is its choices"
            ));
        }
        for c in &choices {
            if c.value.is_empty() || c.label.is_empty() {
                return Err(format!(
                    "the question {id:?} has a choice with an empty value or label"
                ));
            }
        }
        return Ok(Rule::Choice(choices));
    }
    if !choices.is_empty() {
        return Err(format!(
            "the question {id:?} is a {} carrying choices",
            kind.token()
        ));
    }
    match validation {
        Some(v) => Rule::parse(&v).map_err(|why| format!("the question {id:?}: {why}")),
        None => Ok(Rule::None),
    }
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

    const SAMPLE: &str = "\
[[question]]
id = \"username\"
prompt = \"Username\"
type = \"text\"
branch = \"all\"
required = true
validation = \"username\"

[[question]]
id = \"whose\"
prompt = \"Is this for you, or for a body?\"
type = \"choice\"
branch = \"all\"
required = true
choices = [
\t{ value = \"person\", label = \"Just me\" },
\t{ value = \"body\", label = \"A body\" },
]

[[question]]
id = \"body_name\"
prompt = \"The body's name\"
type = \"text\"
branch = \"body\"
required = true

[[question]]
id = \"mail_key\"
prompt = \"Your public key\"
type = \"key\"
branch = \"person\"
required = true
validation = \"mail-key\"

[[question]]
id = \"blessing\"
prompt = \"Blessing?\"
type = \"multiline\"
branch = \"monastic\"
required = true
";

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
    fn a_malformed_question_is_named_not_skipped() {
        // A token outside its vocabulary names the question it came from.
        let unknown_type = SAMPLE.replace("type = \"text\"", "type = \"widget\"");
        let e = parse(&unknown_type).unwrap_err();
        assert!(e.contains("username"), "{e}");
        assert!(e.contains("unknown answer type"), "{e}");

        let unknown_branch = SAMPLE.replace("branch = \"body\"", "branch = \"everyone\"");
        let e = parse(&unknown_branch).unwrap_err();
        assert!(e.contains("body_name"), "{e}");
        assert!(e.contains("unknown branch"), "{e}");

        let unknown_rule = SAMPLE.replace("validation = \"mail-key\"", "validation = \"exists\"");
        let e = parse(&unknown_rule).unwrap_err();
        assert!(e.contains("mail_key"), "{e}");
        assert!(e.contains("exists"), "{e}");

        // A column of the wrong type is a build error rather than a skipped
        // question: `required` is a real boolean, which is one of the reasons
        // the file is TOML.
        let not_a_boolean = SAMPLE.replace("required = true", "required = \"yes\"");
        assert!(parse(&not_a_boolean).is_err());

        // A key that is not a column is refused rather than ignored.
        let typo = SAMPLE.replace("prompt = \"Username\"", "promtp = \"Username\"");
        assert!(parse(&typo).is_err());
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
        let t = "\
[[question]]
id = \"rail\"
prompt = \"How you will pay\"
type = \"choice\"
branch = \"all\"
required = true
choices = [
\t{ value = \"card\", label = \"Card, £20 a year\" },
\t{ value = \"none\", label = \"No charge: anyone who cannot pay\" },
]
";
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
        let bare = SAMPLE.replace(
            "choices = [\n\t{ value = \"person\", label = \"Just me\" },\n\t{ value = \"body\", label = \"A body\" },\n]",
            "",
        );
        let e = parse(&bare).unwrap_err();
        assert!(e.contains("whose"), "{e}");
        assert!(e.contains("no choices"), "{e}");

        let empty = SAMPLE.replace(
            "{ value = \"person\", label = \"Just me\" },",
            "{ value = \"\", label = \"Just me\" },",
        );
        let e = parse(&empty).unwrap_err();
        assert!(e.contains("empty value or label"), "{e}");
    }

    #[test]
    fn choices_belong_to_a_choice_and_everywhere_else_are_refused() {
        let on_a_text = SAMPLE.replace(
            "prompt = \"Username\"",
            "prompt = \"Username\"\nchoices = [\n\t{ value = \"a\", label = \"A\" },\n]",
        );
        let e = parse(&on_a_text).unwrap_err();
        assert!(e.contains("username"), "{e}");
        assert!(e.contains("carrying choices"), "{e}");

        // A choice's rule is its choices, so a validation string beside them is
        // a question that says two things about the same answer.
        let both = SAMPLE.replace(
            "{ value = \"body\", label = \"A body\" },\n]",
            "{ value = \"body\", label = \"A body\" },\n]\nvalidation = \"domain\"",
        );
        let e = parse(&both).unwrap_err();
        assert!(e.contains("its choices"), "{e}");
    }

    #[test]
    fn maxlen_carries_its_number() {
        let t = SAMPLE.replace("validation = \"username\"", "validation = \"maxlen:12\"");
        assert_eq!(parse(&t).unwrap()[0].rule, Rule::MaxLen(12));
    }

    /// The tracked file, read at compile time, so a malformed commit of the data
    /// file fails the build rather than a deployment.
    #[test]
    fn the_shipped_question_list_parses_in_display_order() {
        let list = shipped().unwrap();
        assert_eq!(list.len(), 24);

        let ids: Vec<&str> = list.iter().map(|q| q.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "username",
                "whose",
                "body_name",
                "body_kind",
                "vat",
                "body_domain",
                "body_records",
                "body_addresses",
                "body_account_names",
                "body_mail_key",
                "body_upload_key",
                "body_dns_contact",
                "address_outside",
                "address_ack",
                "mail_key",
                "upload_key",
                "rail",
                "diocese",
                "orders",
                "blessing",
                "cannot_pay",
                "intended_use",
                "anything_else",
                "accept_terms",
            ]
        );

        // The two yesno questions carry no choices: Yes and No are the type's own
        // rendering, so they have no answers of their own to offer.
        for q in list.iter().filter(|q| q.kind == Kind::YesNo) {
            assert_eq!(q.rule, Rule::None, "{}", q.id);
        }

        let whose = list.iter().find(|q| q.id == "whose").unwrap();
        match &whose.rule {
            Rule::Choice(opts) => assert_eq!(opts.len(), 2),
            other => panic!("whose is not a choice: {other:?}"),
        }

        // The person path and the body path both start at the shared questions
        // and every question the branch rules exclude is a body or person one.
        let person: Vec<&str> = shown(&list, true).iter().map(|q| q.id.as_str()).collect();
        let body: Vec<&str> = shown(&list, false).iter().map(|q| q.id.as_str()).collect();
        assert!(person.len() < list.len() && body.len() < list.len());
        assert!(person.contains(&"mail_key") && !person.contains(&"body_mail_key"));
        assert!(body.contains(&"body_mail_key") && !body.contains(&"mail_key"));
        assert!(person.contains(&"blessing") && body.contains(&"blessing"));
    }
}
