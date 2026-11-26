//! Pull search terms and YouTube video ids out of web-filter URLs.
//! Only plain-HTTP URLs (or HTTPS with SSL inspection) carry a query string; otherwise nothing is found.

/// A search the user ran: engine name and the decoded terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Search {
    pub engine: &'static str,
    pub term: String,
}

fn split_url(url: &str) -> (String, String, String) {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let (hostport, tail) = rest.split_once('/').map_or((rest, ""), |(h, t)| (h, t));
    let host = hostport.rsplit('@').next().unwrap_or(hostport);
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();
    let tail = tail.split('#').next().unwrap_or("");
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    (host, format!("/{path}"), query.to_string())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(v) => {
                        out.push(v);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn param<'a>(query: &'a str, names: &[&str]) -> Option<&'a str> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        names.contains(&k).then_some(v)
    })
}

fn clean(term: &str) -> Option<String> {
    let t: String = percent_decode(term)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    let t: String = t.chars().take(200).collect();
    (!t.is_empty()).then_some(t)
}

fn host_is(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

pub fn search_term(url: &str) -> Option<Search> {
    let (host, path, query) = split_url(url);
    let (engine, names, ok): (&'static str, &[&str], bool) =
        if host_is(&host, "google.com") || host.starts_with("google.") || host.contains(".google.")
        {
            ("Google", &["q"], path.starts_with("/search"))
        } else if host_is(&host, "bing.com") {
            ("Bing", &["q"], path.starts_with("/search"))
        } else if host_is(&host, "duckduckgo.com") {
            (
                "DuckDuckGo",
                &["q"],
                matches!(path.as_str(), "/" | "/html" | "/html/" | "/lite" | "/lite/"),
            )
        } else if host_is(&host, "yahoo.com") {
            ("Yahoo", &["p"], path.starts_with("/search"))
        } else if host_is(&host, "yandex.com") || host_is(&host, "yandex.ru") {
            ("Yandex", &["text"], path.starts_with("/search"))
        } else if host_is(&host, "baidu.com") {
            ("Baidu", &["wd"], path.starts_with("/s"))
        } else if host_is(&host, "ecosia.org") {
            ("Ecosia", &["q"], path.starts_with("/search"))
        } else if host_is(&host, "brave.com") {
            ("Brave", &["q"], path.starts_with("/search"))
        } else if host_is(&host, "startpage.com") {
            ("Startpage", &["query"], path.contains("search"))
        } else if host_is(&host, "ask.com") {
            ("Ask", &["q"], path.starts_with("/web"))
        } else if host_is(&host, "youtube.com") {
            ("YouTube", &["search_query"], path.starts_with("/results"))
        } else {
            return None;
        };
    if !ok {
        return None;
    }
    let term = clean(param(&query, names)?)?;
    Some(Search { engine, term })
}

fn valid_id(id: &str) -> Option<String> {
    let id = id.get(..11)?;
    id.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        .then(|| id.to_string())
}

pub fn youtube_video(url: &str) -> Option<String> {
    let (host, path, query) = split_url(url);
    if host == "youtu.be" {
        return valid_id(path.trim_start_matches('/'));
    }
    if host_is(&host, "youtube.com") || host_is(&host, "youtube-nocookie.com") {
        if path.starts_with("/watch") {
            return valid_id(param(&query, &["v"])?);
        }
        for prefix in ["/shorts/", "/embed/", "/live/"] {
            if let Some(rest) = path.strip_prefix(prefix) {
                return valid_id(rest);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_search_is_decoded() {
        let s =
            search_term("http://www.google.com/search?q=best+vpn%20for+%C3%BCbung&hl=en").unwrap();
        assert_eq!(s.engine, "Google");
        assert_eq!(s.term, "best vpn for übung");
    }

    #[test]
    fn non_search_urls_are_ignored() {
        assert!(search_term("http://www.google.com/complete/search?q=abc").is_none());
        assert!(search_term("http://example.com/search?q=abc").is_none());
        assert!(search_term("www.bing.com/search?q=").is_none());
        assert!(search_term("https://www.bing.com/").is_none());
    }

    #[test]
    fn other_engines() {
        assert_eq!(
            search_term("duckduckgo.com/?q=rust+lang").unwrap().term,
            "rust lang"
        );
        assert_eq!(
            search_term("https://search.yahoo.com/search?p=news")
                .unwrap()
                .engine,
            "Yahoo"
        );
        assert_eq!(
            search_term("https://www.youtube.com/results?search_query=lofi+beats")
                .unwrap()
                .engine,
            "YouTube"
        );
    }

    #[test]
    fn youtube_ids() {
        assert_eq!(
            youtube_video("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=10s").as_deref(),
            Some("dQw4w9WgXcQ")
        );
        assert_eq!(
            youtube_video("http://youtu.be/dQw4w9WgXcQ?si=x").as_deref(),
            Some("dQw4w9WgXcQ")
        );
        assert_eq!(
            youtube_video("https://m.youtube.com/shorts/abcDEF12345").as_deref(),
            Some("abcDEF12345")
        );
        assert!(youtube_video("https://www.youtube.com/watch?v=short").is_none());
        assert!(youtube_video("https://example.com/watch?v=dQw4w9WgXcQ").is_none());
    }

    #[test]
    fn control_chars_and_length_are_cleaned() {
        let long = "a".repeat(500);
        let s = search_term(&format!("http://bing.com/search?q=x%00y+{long}")).unwrap();
        assert!(!s.term.contains('\0'));
        assert!(s.term.chars().count() <= 200);
    }
}
