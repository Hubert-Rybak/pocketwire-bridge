//! Just enough DER to read a certificate's expiry and to convert an EC key to PKCS#8.

/// Reads one TLV at the start of `b`: (tag, content, rest).
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | *b.get(2 + i)? as usize;
        }
        (l, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    Some((tag, b.get(hdr..end)?, &b[end..]))
}

fn time_ms(tag: u8, v: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(v).ok()?;
    let (year, rest) = match tag {
        0x17 => {
            let y: i64 = s.get(0..2)?.parse().ok()?;
            (if y >= 50 { 1900 + y } else { 2000 + y }, s.get(2..)?)
        }
        0x18 => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let r = format!("{year:04}-{}-{}T{}:{}:{}Z", rest.get(0..2)?, rest.get(2..4)?, rest.get(4..6)?, rest.get(6..8)?, rest.get(8..10)?);
    crate::util::parse_rfc3339(&r)
}

/// The notAfter time of an X.509 certificate, in Unix milliseconds.
pub fn not_after_ms(cert: &[u8]) -> Option<i64> {
    let (_, cert, _) = tlv(cert)?;
    let (_, tbs, _) = tlv(cert)?;
    let mut rest = tbs;
    let (tag, _, r) = tlv(rest)?;
    if tag == 0xa0 {
        rest = r; // version
    }
    let (_, _, rest) = tlv(rest)?; // serial
    let (_, _, rest) = tlv(rest)?; // signature algorithm
    let (_, _, rest) = tlv(rest)?; // issuer
    let (_, validity, _) = tlv(rest)?;
    let (_, _, v) = tlv(validity)?; // notBefore
    let (tag, na, _) = tlv(v)?;
    time_ms(tag, na)
}

fn enc(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut o = vec![tag];
    let n = content.len();
    if n < 0x80 {
        o.push(n as u8);
    } else if n < 0x100 {
        o.extend([0x81, n as u8]);
    } else {
        o.extend([0x82, (n >> 8) as u8, n as u8]);
    }
    o.extend_from_slice(content);
    o
}

/// Wraps a SEC1 P-256 key ("EC PRIVATE KEY") as PKCS#8, the way Go's MarshalPKCS8PrivateKey does.
pub fn sec1_p256_to_pkcs8(sec1: &[u8]) -> Option<Vec<u8>> {
    let (_, k, _) = tlv(sec1)?;
    let (_, _, rest) = tlv(k)?; // version
    let (_, private, mut rest) = tlv(rest)?;
    let mut public = None;
    while !rest.is_empty() {
        let (tag, v, r) = tlv(rest)?;
        if tag == 0xa1 {
            public = Some(v.to_vec());
        }
        rest = r;
    }
    let mut inner = enc(0x02, &[1]);
    inner.extend(enc(0x04, private));
    if let Some(p) = public {
        inner.extend(enc(0xa1, &p));
    }
    let ec_private_key = enc(0x30, &inner);
    // ecPublicKey, prime256v1
    let alg = [0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let mut body = enc(0x02, &[0]);
    body.extend_from_slice(&alg);
    body.extend(enc(0x04, &ec_private_key));
    Some(enc(0x30, &body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_expiry() {
        let kp = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["x.example".into()]).unwrap();
        p.not_after = rcgen::date_time_ymd(2031, 7, 9);
        let c = p.self_signed(&kp).unwrap();
        assert_eq!(not_after_ms(c.der()).map(|ms| crate::util::rfc3339(ms, false)), Some("2031-07-09T00:00:00Z".into()));
        p.not_after = rcgen::date_time_ymd(2051, 1, 2);
        let c = p.self_signed(&kp).unwrap();
        assert_eq!(not_after_ms(c.der()).map(|ms| crate::util::rfc3339(ms, false)), Some("2051-01-02T00:00:00Z".into()));
    }

    #[test]
    fn converts_sec1() {
        // `openssl ecparam -genkey` (SEC1) and `openssl pkcs8 -topk8` of the same key.
        let sec1 = crate::util::unhex("30770201010420d98d6d9dcc0e07b70f86711b2c0824d5b7efa5c25d0b1e14f87b7462e80bd4a8a00a06082a8648ce3d030107a14403420004bd196a01624c9233ccbe5fd187a559299d9fdec60c5337dee957af5357304be65d2635ffc5daf8e9aa3336d2189a672e284f1840dc254161bc288d5a89d4349b").unwrap();
        let want = crate::util::unhex("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420d98d6d9dcc0e07b70f86711b2c0824d5b7efa5c25d0b1e14f87b7462e80bd4a8a14403420004bd196a01624c9233ccbe5fd187a559299d9fdec60c5337dee957af5357304be65d2635ffc5daf8e9aa3336d2189a672e284f1840dc254161bc288d5a89d4349b").unwrap();
        let p8 = sec1_p256_to_pkcs8(&sec1).unwrap();
        assert_eq!(p8, want);
        let rng = ring::rand::SystemRandom::new();
        assert!(ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &p8, &rng).is_ok());
    }
}
