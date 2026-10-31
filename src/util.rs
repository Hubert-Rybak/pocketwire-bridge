//! Small helpers: randomness, hex, time stamps, HTML and URL encoding.

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

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
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

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
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

/// Time of day (HH:MM:SS, UTC) for pages; a script on the page shows it in local time.
pub fn clock(ms: i64) -> String {
    rfc3339(ms, false)[11..19].to_string()
}

/// Parses RFC 3339 (any offset, any number of decimals) into milliseconds.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b't' || b[10] == b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    let mut i = 19;
    let mut frac_ms = 0i64;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let digits = &s[start..i];
        let mut v = 0i64;
        for (k, c) in digits.chars().take(3).enumerate() {
            v += (c as i64 - '0' as i64) * [100, 10, 1][k];
        }
        frac_ms = v;
    }
    let offset_secs = match b.get(i)? {
        b'Z' | b'z' => 0,
        sign @ (b'+' | b'-') => {
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6)?;
            let o = oh * 3600 + om * 60;
            if *sign == b'+' {
                o
            } else {
                -o
            }
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo, d);
    let secs = days * 86400 + h * 3600 + mi * 60 + se - offset_secs;
    Some(secs * 1000 + frac_ms)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_roundtrip() {
        let ms = parse_rfc3339("2026-10-31T11:00:01.123456789+01:00").unwrap();
        assert_eq!(rfc3339(ms, true), "2026-10-31T10:00:01.123Z");
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339(0, false), "1970-01-01T00:00:00Z");
        assert_eq!(parse_rfc3339("2000-02-29T23:59:59-05:30").map(|v| rfc3339(v, false)), Some("2000-03-01T05:29:59Z".into()));
        assert_eq!(parse_rfc3339("nope"), None);
    }

    #[test]
    fn escaping() {
        assert_eq!(esc(r#"<a href="x">'&'</a>"#), "&lt;a href=&#34;x&#34;&gt;&#39;&amp;&#39;&lt;/a&gt;");
        assert_eq!(query_escape("Sending. ą+"), "Sending.+%C4%85%2B");
        assert_eq!(query_unescape("Sending.+%C4%85%2B%"), "Sending. ą+%");
        assert_eq!(parse_query("a=1&b=x+y&c"), vec![("a".into(), "1".into()), ("b".into(), "x y".into()), ("c".into(), "".into())]);
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(unhex(&hex(&[0, 1, 254, 255])), Some(vec![0, 1, 254, 255]));
        assert_eq!(unhex("zz"), None);
        assert_eq!(truncate("ąę", 3), "ą");
    }
}
