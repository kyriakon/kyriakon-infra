//! The media type a served file is announced as.
//!
//! A table rather than a crate: the set of extensions a member site publishes is
//! small, the files are public, and a dependency that guesses would still be
//! wrong for the one extension someone cares about. An unknown extension is
//! `application/octet-stream`, which every client downloads rather than renders.

/// The type for `name`, from its extension, case-insensitively.
pub fn media_type(name: &str) -> &'static str {
    let Some((_, extension)) = name.rsplit_once('.') else {
        return "application/octet-stream";
    };
    match extension.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" | "asc" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "xml" => "application/xml",
        "atom" => "application/atom+xml",
        "rss" => "application/rss+xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/vnd.microsoft.icon",
        "avif" => "image/avif",
        "pdf" => "application/pdf",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        // Gemini's own format. A capsule serves it as a file like any other, and
        // a client renders it when the type says so.
        "gmi" => "text/gemini; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::media_type;

    #[test]
    fn the_type_follows_the_extension() {
        assert_eq!(media_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(media_type("page.gmi"), "text/gemini; charset=utf-8");
        assert_eq!(media_type("LOGO.PNG"), "image/png");
        assert_eq!(media_type("archive.tar.gz"), "application/octet-stream");
        assert_eq!(media_type("README"), "application/octet-stream");
    }
}
