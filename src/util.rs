//! Small helpers: randomness, hex, time stamps, HTML and URL encoding, opening a browser.

use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom, SystemRandom};

/// Fills a buffer of `n` random bytes from the operating system.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    SystemRandom::new().fill(&mut b).expect("system random number generator");
    b
}

pub fn random_hex(n: usize) -> String {
    hex(&random_bytes(n))
}

pub fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

pub fn hmac_hex(key: &[u8], msg: &[u8]) -> String {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    hex(ring::hmac::sign(&k, msg).as_ref())
}

/// Constant-time string comparison for secrets.
pub fn eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    std::hint::black_box(d) == 0
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn now_secs() -> i64 {
    now_ms().div_euclid(1000)
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

/// Formats a time as RFC 3339 in UTC; with `millis`, keeps three decimals.
pub fn rfc3339(ms: i64, millis: bool) -> String {
    let secs = ms.div_euclid(1000);
    let (y, mo, d) = civil_from_days(secs.div_euclid(86400));
    let t = secs.rem_euclid(86400);
    let base = format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}", t / 3600, t / 60 % 60, t % 60);
    if millis {
        format!("{base}.{:03}Z", ms.rem_euclid(1000))
    } else {
        base + "Z"
    }
}

/// Escapes text for HTML element content and quoted attribute values.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&#34;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

/// Percent-encodes a query parameter value (spaces as +).
pub fn query_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// Decodes a form or query component (+ and %XX).
pub fn query_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => match std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                Some(v) => {
                    out.push(v);
                    i += 2;
                }
                None => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses `a=1&b=2` into pairs.
pub fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (query_unescape(k), query_unescape(v)),
            None => (query_unescape(p), String::new()),
        })
        .collect()
}

pub fn get<'a>(pairs: &'a [(String, String)], key: &str) -> &'a str {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).unwrap_or("")
}

/// Cuts a string to at most `n` bytes on a character boundary.
pub fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let mut end = n;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Opens a URL with the desktop's default browser.
pub fn open_browser(url: &str) -> Result<(), String> {
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    } else if cfg!(windows) {
        let mut c = std::process::Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler").arg(url);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    cmd.spawn().map(|_| ()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_times() {
        assert_eq!(rfc3339(1_793_440_801_123, true), "2026-10-31T10:00:01.123Z");
        assert_eq!(rfc3339(0, false), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_868_799_000, false), "2000-02-29T23:59:59Z");
    }

    #[test]
    fn escaping() {
        assert_eq!(esc(r#"<a href="x">'&'</a>"#), "&lt;a href=&#34;x&#34;&gt;&#39;&amp;&#39;&lt;/a&gt;");
        assert_eq!(query_escape("Sending. ą+"), "Sending.+%C4%85%2B");
        assert_eq!(query_unescape("Sending.+%C4%85%2B%"), "Sending. ą+%");
        assert_eq!(parse_query("a=1&b=x+y&c"), vec![("a".into(), "1".into()), ("b".into(), "x y".into()), ("c".into(), "".into())]);
    }

    #[test]
    fn hex_and_truncate() {
        assert_eq!(hex(&[0, 1, 254, 255]), "0001feff");
        assert_eq!(truncate("ąę", 3), "ą");
    }
}
