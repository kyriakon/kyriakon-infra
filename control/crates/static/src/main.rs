//! The member content responder: the process `kyriakon-control-static`.
//!
//! `kyriakon-control-static [--config PATH]`
//!
//! Both front-ends hand a member's site here rather than serving the tree
//! themselves. httpd and gmid cannot refuse a symlink: a member who plants one in
//! their writable root reaches every other member's tree and the platform's
//! `.git`, because the `root` a vhost names is chrooted to `/home/www`, where
//! every member's tree lives beside every other's (#815).
//!
//! The two daemons still terminate TLS and decide which host a request is for;
//! this process is told the host and serves that member's tree from a socket
//! inside the same chroot. The path within the tree is resolved by the crate's
//! library, one component at a time with `O_NOFOLLOW`, so the file that comes back
//! was reached without a link being followed.
//!
//! What a request may not do is as important as what it may. The host is the
//! front-end's own configured name, but it is still checked before it is joined
//! into a path here, because a name carrying a separator would step out of the
//! root before the resolver ever saw the request. The request path carries no
//! meaning beyond names: a dot component, an empty one, or a name beginning with a
//! dot is a refusal.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use kyriakon_control_core::fastcgi::{self, Http, Reply, Request};
use kyriakon_control_core::util::{self, percent_decode};
use kyriakon_control_core::Error;
use kyriakon_control_static::{open, Refusal, Served};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};

/// The web tree's index. A directory request serves this and never a listing,
/// which would publish names the member did not link.
const WWW_INDEX: &str = "index.html";
/// The capsule's tree and its index. A gemini client renders `text/gemini`, so a
/// capsule's `index.html` would arrive as raw markup.
const GEMINI_INDEX: &str = "index.gmi";

/// The most of one file this process will hold in memory to send it. A member
/// site is pages and images; the cap is what stops one upload from pinning a
/// megabyte count per concurrent download.
///
/// shortcut: files over this are refused rather than streamed, raise it (or
/// stream through the wire) if a member publishes something larger.
const MAX_FILE: usize = 16 * 1024 * 1024;

/// The most of a request body this process will read. A static request has none:
/// httpd sends the form posts to the control plane's socket, not this one.
const MAX_BODY: usize = 0;

/// The wait before the next accept after an error that is not the connection's.
const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

#[derive(Clone, serde::Deserialize)]
struct Config {
    /// The directory holding every member's tree, which is httpd's chroot root.
    root: PathBuf,
    /// httpd's socket, inside that root so the daemon reaches it after chroot.
    httpd_socket: PathBuf,
    /// gmid's socket, likewise.
    gemini_socket: PathBuf,
    /// One file per host whose tree is not named after it. A group site is
    /// served under the body's own domain while its files live in the site
    /// owner's member tree, so the host alone does not choose the tree.
    hosts: PathBuf,
}

impl Config {
    fn load(path: &Path) -> Result<Config, Error> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            what: "read the configuration",
            path: Some(path.into()),
            source,
        })?;
        toml::from_str(&text)
            .map_err(|source| Error::Failed(format!("{} does not parse: {source}", path.display())))
    }

    /// The tree a request for `host` is served from, or `None` when the name is
    /// not a hostname this server will join into a path.
    ///
    /// The name comes from the front-end's own configuration rather than from the
    /// client, but it is a path component here, so the alphabet check is what keeps
    /// that reading local: a name with a separator, or one beginning with a dot,
    /// could reach outside `root`, and the resolver cannot refuse what it is never
    /// given.
    fn tree(&self, front_end: FrontEnd, host: &str) -> Option<PathBuf> {
        if !is_name(host) {
            return None;
        }
        let name = match self.alias(host) {
            Some(alias) if is_name(&alias) => alias,
            Some(_) => return None,
            None => host.to_string(),
        };
        Some(self.root.join(name).join(front_end.subdirectory()))
    }

    /// The tree name for a host whose own name is not its directory.
    ///
    /// scripts/provision-group-web.sh writes one file per group site, because the
    /// vhost is named for the body's domain and the files live in the site
    /// owner's member tree. The directory is root-owned, so a member cannot put a
    /// name in it, and the value is checked against the same alphabet before it is
    /// joined, so an entry cannot point outside `root` either.
    fn alias(&self, host: &str) -> Option<String> {
        let name = std::fs::read_to_string(self.hosts.join(host)).ok()?;
        let name = name.trim();
        (!name.is_empty()).then(|| name.to_string())
    }
}

/// Which front-end asked. Each listener answers for one of them, so the channel
/// is decided by the socket the connection arrived on, not by a variable in the
/// request: a peer that sent the other front-end's spelling could not make this
/// process frame an answer for it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FrontEnd {
    Httpd,
    Gemini,
}

impl FrontEnd {
    fn word(self) -> &'static str {
        match self {
            FrontEnd::Httpd => "httpd",
            FrontEnd::Gemini => "gmid",
        }
    }

    fn subdirectory(self) -> &'static str {
        match self {
            FrontEnd::Httpd => "www",
            FrontEnd::Gemini => "gemini",
        }
    }

    fn index(self) -> &'static str {
        match self {
            FrontEnd::Httpd => WWW_INDEX,
            FrontEnd::Gemini => GEMINI_INDEX,
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        util::report(&e, "serving member sites");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Error> {
    let mut cfg_path = PathBuf::from("/etc/onboard/static.toml");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                cfg_path = PathBuf::from(
                    args.next()
                        .ok_or_else(|| Error::Failed("--config needs a path".to_string()))?,
                );
            }
            other => {
                return Err(Error::Failed(format!(
                    "unknown argument {other:?}; usage: kyriakon-control-static [--config PATH]"
                )))
            }
        }
    }

    let cfg = Arc::new(Config::load(&cfg_path)?);
    let httpd = bind(&cfg.httpd_socket)?;
    let gemini = bind(&cfg.gemini_socket)?;
    util::log(&format!(
        "kyriakon-control-static: httpd {}, gemini {}, root {}",
        cfg.httpd_socket.display(),
        cfg.gemini_socket.display(),
        cfg.root.display()
    ));
    tokio::try_join!(
        accept(httpd, cfg.clone(), FrontEnd::Httpd),
        accept(gemini, cfg, FrontEnd::Gemini),
    )
    .map(|_| ())
}

/// Bind one socket, replacing whatever a previous run left at the path, with mode
/// 0660 so the group the socket directory carries is what decides who may
/// connect. Same shape as the control plane's own bind, for the same reasons.
fn bind(path: &Path) -> Result<UnixListener, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => std::fs::remove_file(path).map_err(|source| Error::Io {
            what: "clear the path for",
            path: Some(path.into()),
            source,
        })?,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(Error::Io {
                what: "check",
                path: Some(path.into()),
                source,
            })
        }
    }
    let listener = UnixListener::bind(path).map_err(|source| Error::Io {
        what: "listen on",
        path: Some(path.into()),
        source,
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).map_err(|source| {
        Error::Io {
            what: "set the mode on",
            path: Some(path.into()),
            source,
        }
    })?;
    Ok(listener)
}

/// Accept connections for as long as the process lives. An accept error is a
/// connection the front-end dropped, not the listener: returning it would take
/// the other front-end down with it.
async fn accept(
    listener: UnixListener,
    cfg: Arc<Config>,
    front_end: FrontEnd,
) -> Result<(), Error> {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                util::log(&format!(
                    "kyriakon-control-static: cannot accept a connection: {e}"
                ));
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = connection(stream, &cfg, front_end).await {
                e.report("serving a connection");
            }
        });
    }
}

/// Answer the requests on one connection. gmid asks for the connection to be
/// kept, httpd does not, so the loop runs until the peer closes or says so.
async fn connection(stream: UnixStream, cfg: &Config, front_end: FrontEnd) -> Result<(), Error> {
    let (mut reader, mut writer) = stream.into_split();
    loop {
        let request = fastcgi::read_request(&mut reader, MAX_BODY)
            .await
            .map_err(|e| Error::Failed(format!("cannot read a request: {e}")))?;
        let Some(request) = request else {
            return Ok(());
        };
        let (reply, route) = answer(cfg, front_end, &request);
        util::log(&format!(
            "kyriakon-control-static: {} {} {}",
            front_end.word(),
            route,
            reply.code()
        ));
        let bytes = fastcgi::reply_bytes(&reply, request.id());
        writer.write_all(&bytes).await.map_err(|source| Error::Io {
            what: "write the reply",
            path: None,
            source,
        })?;
        writer.flush().await.map_err(|source| Error::Io {
            what: "flush the reply",
            path: None,
            source,
        })?;
        if !request.keep_conn {
            return Ok(());
        }
    }
}

/// One request's reply, and the path the log line names. The path is the decoded
/// one without its query: the query is the member's, and one that carries an
/// answer should not be written down.
fn answer(cfg: &Config, front_end: FrontEnd, request: &Request) -> (Reply, String) {
    let path = match front_end {
        // httpd passes the client's spelling of the request line, query and all.
        FrontEnd::Httpd => percent_decode(
            request
                .value("REQUEST_URI")
                .split('?')
                .next()
                .unwrap_or_default(),
            false,
        ),
        // gmid decodes and strips the leading slash before it sends it.
        FrontEnd::Gemini => request.value("GEMINI_URL_PATH").to_string(),
    };
    let host = normalise_host(request.value("SERVER_NAME"));
    let route = format!("{host}{path}");
    let Some(root) = cfg.tree(front_end, &host) else {
        return (refuse(front_end), route);
    };
    match open(&root, &path, front_end.index()) {
        Ok(Served::File {
            file,
            media,
            modified,
        }) => {
            let last_modified = modified.and_then(http_date);
            // A browser that already holds this copy asks with the date it was
            // given; answering 304 keeps a member's page from being re-sent on
            // every navigation, which httpd's own file server did for the vhosts
            // this replaced.
            if front_end == FrontEnd::Httpd && unchanged(modified, request) {
                return (not_modified(media, last_modified), route);
            }
            match read_capped(file) {
                Some(body) => (serve(front_end, media, body, last_modified), route),
                None => (too_large(front_end), route),
            }
        }
        Ok(Served::Redirect) => (redirect(front_end, &host, &path), route),
        // Both refusals are the same answer: a client that could tell "no such
        // file" from "not a file" would learn which of its guesses resolved.
        Err(Refusal::Missing | Refusal::NotAFile) => (refuse(front_end), route),
    }
}

/// The file's bytes, or `None` when it is over the cap.
fn read_capped(file: std::fs::File) -> Option<Vec<u8>> {
    let metadata = file.metadata().ok()?;
    if metadata.len() > MAX_FILE as u64 {
        return None;
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    // `take` rather than a second length check, so a file that grew between the
    // metadata read and this one cannot read past the cap.
    file.take(MAX_FILE as u64 + 1).read_to_end(&mut body).ok()?;
    (body.len() <= MAX_FILE).then_some(body)
}

/// A file's bytes, framed for the front-end that asked. The web announces the
/// type in a header; a capsule announces it in the reply line, which is the only
/// place a gemini client reads it.
fn serve(front_end: FrontEnd, media: &str, body: Vec<u8>, last_modified: Option<String>) -> Reply {
    match front_end {
        FrontEnd::Httpd => {
            let mut http = Http::file(200, media, body);
            if let Some(date) = last_modified {
                http = http.with_header("Last-Modified", date);
            }
            Reply::Http(http)
        }
        FrontEnd::Gemini => Reply::gemini(20, media, body),
    }
}

/// Whether the client's copy is still the file on disk. The header is only
/// present on httpd's requests: a gemini request has none.
fn unchanged(modified: Option<SystemTime>, request: &Request) -> bool {
    let (Some(modified), Some(since)) = (
        modified,
        parse_http_date(request.value("HTTP_IF_MODIFIED_SINCE")),
    ) else {
        return false;
    };
    match modified.duration_since(UNIX_EPOCH) {
        Ok(age) => age.as_secs() <= since.unix_timestamp().max(0) as u64,
        Err(_) => false,
    }
}

/// A 304 carries the same `Content-Type` the 200 would have, which is what the
/// specification allows, and no body.
fn not_modified(media: &str, last_modified: Option<String>) -> Reply {
    let mut http = Http::file(304, media, Vec::new());
    if let Some(date) = last_modified {
        http = http.with_header("Last-Modified", date);
    }
    Reply::Http(http)
}

/// An HTTP date, as the header carries it: `Sun, 06 Nov 1994 08:49:37 GMT`.
///
/// One form only. The specification lets a sender produce this one and lets a
/// recipient read two obsolete ones as well, and neither front-end here sends
/// those; the `time` crate does the calendar arithmetic and this does the
/// spelling, so no format description has to be parsed at startup.
fn http_date(modified: SystemTime) -> Option<String> {
    let at = OffsetDateTime::from(modified);
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let day = DAYS[at.weekday().number_days_from_monday() as usize];
    let month = MONTHS[at.month() as usize - 1];
    Some(format!(
        "{day}, {:02} {month} {} {:02}:{:02}:{:02} GMT",
        at.day(),
        at.year(),
        at.hour(),
        at.minute(),
        at.second()
    ))
}

fn parse_http_date(raw: &str) -> Option<OffsetDateTime> {
    // `Sun, 06 Nov 1994 08:49:37 GMT`
    let (_, rest) = raw.trim().split_once(", ")?;
    let mut fields = rest.split_whitespace();
    let day: u8 = fields.next()?.parse().ok()?;
    let month = Month::try_from(match fields.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
    .ok()?;
    let year: i32 = fields.next()?.parse().ok()?;
    let clock = fields.next()?;
    if fields.next()? != "GMT" || fields.next().is_some() {
        return None;
    }
    let mut hms = clock.split(':');
    let hour: u8 = hms.next()?.parse().ok()?;
    let minute: u8 = hms.next()?.parse().ok()?;
    let second: u8 = hms.next()?.parse().ok()?;
    if hms.next().is_some() {
        return None;
    }
    Some(
        PrimitiveDateTime::new(
            Date::from_calendar_date(year, month, day).ok()?,
            Time::from_hms(hour, minute, second).ok()?,
        )
        .assume_utc(),
    )
}

fn refuse(front_end: FrontEnd) -> Reply {
    match front_end {
        FrontEnd::Httpd => Reply::file(404, "text/plain; charset=utf-8", b"Not found\n".to_vec()),
        FrontEnd::Gemini => Reply::gemini(51, "Not found", ""),
    }
}

fn too_large(front_end: FrontEnd) -> Reply {
    match front_end {
        FrontEnd::Httpd => Reply::file(
            413,
            "text/plain; charset=utf-8",
            b"This file is too large to serve.\n".to_vec(),
        ),
        FrontEnd::Gemini => Reply::gemini(59, "File too large", ""),
    }
}

/// A directory asked for without its trailing separator: answer with the same
/// path and the separator, so a relative link in the page resolves against the
/// directory rather than against its parent.
///
/// The path is encoded on the way out, because it arrived decoded. A member may
/// name a directory with a space, a non-ASCII byte or a control character, and a
/// raw CR or LF in a header splits it: httpd reads the reply as a header block
/// line by line, so an unencoded newline in `Location` would become a header the
/// member chose.
fn redirect(front_end: FrontEnd, host: &str, path: &str) -> Reply {
    let path = encode_path(path.trim_end_matches('/'));
    match front_end {
        FrontEnd::Httpd => Reply::Http(fastcgi::Http::moved(&format!("{path}/"))),
        FrontEnd::Gemini => Reply::gemini(
            31,
            &format!("gemini://{host}/{}/", path.trim_start_matches('/')),
            "",
        ),
    }
}

/// A path as a URL carries it: everything but the unreserved characters and `/`
/// is percent-encoded.
fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The host a request names, lowercased and without a port.
///
/// gmid sends the host from the request URI and httpd the `Host` header relayd
/// passed through, so either can carry a port or capitals that the member's
/// directory name does not. Both are spelling, not identity: the directory is
/// named for the member's lowercase name and nothing else.
fn normalise_host(host: &str) -> String {
    host.split(':').next().unwrap_or(host).to_ascii_lowercase()
}

/// Whether a name may be joined into the root as one directory.
///
/// The host and a group site's tree name are both path components, so the
/// alphabet is what keeps the reading local: a name with a separator, or one
/// beginning with a dot, could reach outside `root`, and the resolver cannot
/// refuse what it is never given.
fn is_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use kyriakon_control_core::fastcgi::fixture;
    use std::os::unix::fs::symlink;

    /// A root with one member's tree, a file beside it that a link aims at, and
    /// the two links #815 is about.
    fn fixture_root() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "kyriakon-static-wire-{}-{:x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let alice = base.join("alice.kyriakon.net/www");
        let bob = base.join("bob.kyriakon.net/www");
        std::fs::create_dir_all(alice.join("sub")).unwrap();
        let capsule = base.join("alice.kyriakon.net/gemini");
        std::fs::create_dir_all(capsule.join("sub")).unwrap();
        std::fs::write(capsule.join("index.gmi"), b"# capsule\n").unwrap();
        std::fs::write(capsule.join("sub/index.gmi"), b"# sub\n").unwrap();
        std::fs::create_dir_all(&bob).unwrap();
        std::fs::write(alice.join("index.html"), b"alice").unwrap();
        std::fs::write(alice.join("sub/index.html"), b"sub").unwrap();
        std::fs::write(alice.join("my page.html"), b"spaced").unwrap();
        std::fs::write(bob.join("secret.html"), b"bob").unwrap();
        symlink("../../bob.kyriakon.net/www/secret.html", alice.join("leak")).unwrap();
        symlink(bob.join("secret.html"), alice.join("gitleak")).unwrap();
        base
    }

    fn config(root: PathBuf) -> Config {
        Config {
            root: root.clone(),
            httpd_socket: PathBuf::new(),
            gemini_socket: PathBuf::new(),
            hosts: root.join("static-hosts"),
        }
    }

    /// The whole path a front-end takes: request bytes in, reply bytes out.
    async fn httpd(cfg: &Config, uri: &str) -> (u16, String) {
        let raw = fixture::httpd(
            &[("SERVER_NAME", "alice.kyriakon.net"), ("REQUEST_URI", uri)],
            b"",
        );
        let request = fastcgi::read_request(&mut &raw[..], 1024)
            .await
            .unwrap()
            .unwrap();
        let (reply, _) = answer(cfg, FrontEnd::Httpd, &request);
        let (body, _) = fixture::reply(&fastcgi::reply_bytes(&reply, 1));
        let text = String::from_utf8_lossy(&body).into_owned();
        (reply.code(), text)
    }

    async fn gemini(cfg: &Config, path: &str) -> (u16, String) {
        let raw = fixture::gmid(&[
            ("SERVER_NAME", "alice.kyriakon.net"),
            ("GEMINI_URL_PATH", path),
        ]);
        let request = fastcgi::read_request(&mut &raw[..], 1024)
            .await
            .unwrap()
            .unwrap();
        let (reply, _) = answer(cfg, FrontEnd::Gemini, &request);
        let (body, _) = fixture::reply(&fastcgi::reply_bytes(&reply, 1));
        (reply.code(), String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn a_members_file_is_served_with_its_type_and_its_bytes() {
        let cfg = config(fixture_root());
        let (code, body) = httpd(&cfg, "/index.html").await;
        assert_eq!(code, 200);
        assert!(body.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert!(body.ends_with("\r\n\r\nalice"));

        let (code, body) = httpd(&cfg, "/my%20page.html").await;
        assert_eq!(code, 200, "{body}");
        assert!(body.ends_with("spaced"));

        let (code, body) = gemini(&cfg, "index.gmi").await;
        assert_eq!(code, 20, "{body}");
        assert!(
            body.starts_with("20 text/gemini; charset=utf-8\r\n"),
            "{body}"
        );
    }

    /// The two links #815 describes, over the wire this process now serves.
    #[tokio::test]
    async fn a_link_out_of_the_tree_is_a_404_on_both_front_ends() {
        let cfg = config(fixture_root());
        for uri in [
            "/leak",
            "/gitleak",
            "/.git/config",
            "/../bob.kyriakon.net/www/secret.html",
        ] {
            let (code, body) = httpd(&cfg, uri).await;
            assert_eq!(code, 404, "{uri}: {body}");
            assert!(!body.contains("bob"), "{uri}: {body}");
        }
        for path in ["leak", "gitleak", ".git/config", "..%2Fbob"] {
            let (code, body) = gemini(&cfg, path).await;
            assert_eq!(code, 51, "{path}: {body}");
            assert!(!body.contains("bob"), "{path}: {body}");
        }
    }

    #[tokio::test]
    async fn a_directory_without_its_separator_is_a_redirect() {
        let cfg = config(fixture_root());
        let (code, body) = httpd(&cfg, "/sub").await;
        assert_eq!(code, 301);
        assert!(body.contains("Location: /sub/\r\n"), "{body}");

        let (code, body) = gemini(&cfg, "sub").await;
        assert_eq!(code, 31, "{body}");
        assert!(
            body.starts_with("31 gemini://alice.kyriakon.net/sub/\r\n"),
            "{body}"
        );
    }

    /// A group site is served under the body's own domain while its files live in
    /// the site owner's member tree, so the host names a file rather than a
    /// directory. This is the case that was 404ing before the map existed.
    #[tokio::test]
    async fn a_host_with_a_tree_of_its_own_is_served_from_that_tree() {
        let cfg = config(fixture_root());
        std::fs::create_dir_all(cfg.hosts.join("parish.example").parent().unwrap()).unwrap();
        std::fs::write(cfg.hosts.join("parish.example"), "alice.kyriakon.net\n").unwrap();

        let raw = fixture::httpd(
            &[
                ("SERVER_NAME", "parish.example"),
                ("REQUEST_URI", "/index.html"),
            ],
            b"",
        );
        let request = fastcgi::read_request(&mut &raw[..], 1024)
            .await
            .unwrap()
            .unwrap();
        let (reply, _) = answer(&cfg, FrontEnd::Httpd, &request);
        let (body, _) = fixture::reply(&fastcgi::reply_bytes(&reply, 1));
        assert_eq!(reply.code(), 200);
        assert!(String::from_utf8_lossy(&body).ends_with("alice"));

        // An entry is a path component too, so one with a separator is refused
        // rather than joined.
        std::fs::write(cfg.hosts.join("parish.example"), "../bob.kyriakon.net\n").unwrap();
        assert!(cfg.tree(FrontEnd::Httpd, "parish.example").is_none());
    }

    #[test]
    fn a_host_normalises_before_it_names_a_tree() {
        assert_eq!(normalise_host("Alice.Kyriakon.Net"), "alice.kyriakon.net");
        assert_eq!(
            normalise_host("alice.kyriakon.net:443"),
            "alice.kyriakon.net"
        );
        assert_eq!(
            normalise_host("alice.kyriakon.net:8080"),
            "alice.kyriakon.net"
        );
        assert_eq!(normalise_host(""), "");
    }

    /// The host is a path component before the resolver is reached, so a name
    /// that could step out of the root never becomes one.
    #[tokio::test]
    async fn a_host_that_is_not_a_hostname_is_refused() {
        let cfg = config(fixture_root());
        for host in ["..", ".", "../alice.kyriakon.net", "alice/../../bob", ""] {
            assert!(cfg.tree(FrontEnd::Httpd, host).is_none(), "{host:?}");
            let raw = fixture::httpd(
                &[("SERVER_NAME", host), ("REQUEST_URI", "/index.html")],
                b"",
            );
            let request = fastcgi::read_request(&mut &raw[..], 1024)
                .await
                .unwrap()
                .unwrap();
            let (reply, _) = answer(&cfg, FrontEnd::Httpd, &request);
            assert_eq!(reply.code(), 404, "{host:?}");
        }
    }

    /// A directory name a member chose must not be able to split the reply.
    #[tokio::test]
    async fn a_redirect_encodes_the_name_it_carries() {
        let cfg = config(fixture_root());
        let www = cfg.root.join("alice.kyriakon.net/www");

        // A control character in a directory name would end the header line.
        std::fs::create_dir_all(www.join("evil\r\nX-Injected: yes")).unwrap();
        let (code, text) = httpd_answer(&cfg, "/evil%0D%0AX-Injected:%20yes").await;
        assert_eq!(code, 301);
        assert!(
            text.contains("Location: /evil%0D%0AX-Injected%3A%20yes/\r\n"),
            "{text}"
        );
        // One status line, one Content-Type, one Location, and the blank line.
        assert_eq!(text.matches("\r\n").count(), 4, "{text}");

        // A space is a legal directory name and an illegal URL, so it is encoded.
        std::fs::create_dir_all(www.join("my dir")).unwrap();
        let (code, text) = httpd_answer(&cfg, "/my%20dir").await;
        assert_eq!(code, 301);
        assert!(text.contains("Location: /my%20dir/\r\n"), "{text}");
    }

    /// The one bound on what a download may cost in memory: the cap is checked
    /// on the metadata and again while reading, because a file can grow between
    /// the two.
    #[test]
    fn a_file_over_the_cap_is_refused_and_one_at_it_is_not() {
        let cfg = config(fixture_root());
        let www = cfg.root.join("alice.kyriakon.net/www");
        let at_cap = |code: u16, path: &str| {
            let cfg = &cfg;
            let path = path.to_string();
            (
                code,
                block_on(async move { httpd_answer(cfg, &path).await.0 }),
            )
        };

        std::fs::write(www.join("big.bin"), vec![0u8; MAX_FILE + 1]).unwrap();
        std::fs::write(www.join("edge.bin"), vec![0u8; MAX_FILE]).unwrap();
        let (want, got) = at_cap(413, "/big.bin");
        assert_eq!(got, want);
        let (want, got) = at_cap(200, "/edge.bin");
        assert_eq!(got, want);
    }

    /// One request through the answer path, for the tests above.
    async fn httpd_answer(cfg: &Config, uri: &str) -> (u16, String) {
        httpd_env(cfg, &[("REQUEST_URI", uri)]).await
    }

    async fn httpd_env(cfg: &Config, env: &[(&str, &str)]) -> (u16, String) {
        let mut env = env.to_vec();
        env.insert(0, ("SERVER_NAME", "alice.kyriakon.net"));
        let raw = fixture::httpd(&env, b"");
        let request = fastcgi::read_request(&mut &raw[..], 1024)
            .await
            .unwrap()
            .unwrap();
        let (reply, _) = answer(cfg, FrontEnd::Httpd, &request);
        let (body, _) = fixture::reply(&fastcgi::reply_bytes(&reply, 1));
        (reply.code(), String::from_utf8_lossy(&body).into_owned())
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// A page that has not changed is not sent again: the reply carries its
    /// time, and a client that quotes that time back gets 304.
    #[tokio::test]
    async fn a_client_that_holds_the_copy_is_told_it_is_current() {
        let cfg = config(fixture_root());
        let path = cfg.root.join("alice.kyriakon.net/www/index.html");
        let when = UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(when)
            .unwrap();
        let date = http_date(when).expect("the change time formats");

        let (code, body) = httpd_answer(&cfg, "/index.html").await;
        assert_eq!(code, 200);
        assert!(
            body.contains(&format!("Last-Modified: {date}\r\n")),
            "{body}"
        );

        let (code, body) = httpd_env(
            &cfg,
            &[
                ("REQUEST_URI", "/index.html"),
                ("HTTP_IF_MODIFIED_SINCE", &date),
            ],
        )
        .await;
        assert_eq!(code, 304, "{body}");
        assert!(
            body.contains(&format!("Last-Modified: {date}\r\n")),
            "{body}"
        );
        assert!(!body.contains("alice"), "a 304 carries no body: {body}");

        // A copy from before the change is not current, so the page is sent.
        let earlier = http_date(when - std::time::Duration::from_secs(60)).unwrap();
        let (code, body) = httpd_env(
            &cfg,
            &[
                ("REQUEST_URI", "/index.html"),
                ("HTTP_IF_MODIFIED_SINCE", &earlier),
            ],
        )
        .await;
        assert_eq!(code, 200);
        assert!(body.ends_with("alice"), "{body}");

        // A date this server cannot read is not a reason to answer 304.
        let (code, _) = httpd_env(
            &cfg,
            &[
                ("REQUEST_URI", "/index.html"),
                ("HTTP_IF_MODIFIED_SINCE", "yesterday"),
            ],
        )
        .await;
        assert_eq!(code, 200);
    }

    #[test]
    fn a_query_is_cut_before_the_path_is_decoded() {
        let uri = |raw: &str| percent_decode(raw.split('?').next().unwrap_or_default(), false);
        assert_eq!(uri("/my%20page.html?x=1"), "/my page.html");
        assert_eq!(uri("/%2e%2e/x"), "/../x");
        assert_eq!(uri("/100%"), "/100%");
        assert_eq!(uri("/a%zz"), "/a%zz");
    }
}
