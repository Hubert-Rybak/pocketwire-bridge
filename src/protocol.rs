//! The Pocketwire device protocol v1: frames, the device key and the checks the server also makes.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde::{Deserialize, Serialize};

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// Any JSON frame; fields are optional depending on `type`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Frame {
    #[serde(rename = "type")]
    pub typ: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub nonce: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub device_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub signature: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub app_version: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<CommandParams>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub approval: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub expires_at: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,

    // Private messages (local MCP): the Bridge asks the server for a decision without revealing
    // the number or the text.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub request_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub to_tag: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub body_len: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub segments: i64,
    #[serde(skip_serializing_if = "is_false")]
    pub trusted: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message_id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub numbers: Vec<String>,

    // Blind relay: the Bridge checks a bearer token by its hash.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub token_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hostname: String,
}

impl Frame {
    pub fn new(typ: &str) -> Frame {
        Frame { typ: typ.to_string(), ..Default::default() }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CommandParams {
    pub to: String,
    pub body: String,
}

/// The exact message a device signs in reply to a challenge.
pub fn challenge_string(nonce: &str, device_id: &str) -> String {
    format!("pocketwire-v1|{nonce}|{device_id}")
}

/// What a Bridge signs to open its blind-relay tunnel.
pub fn tunnel_challenge_string(nonce: &str, device_id: &str) -> String {
    format!("pocketwire-tunnel-v1|{nonce}|{device_id}")
}

/// The device's EC P-256 key. Only the public key ever leaves this computer.
pub struct DeviceKey {
    pair: EcdsaKeyPair,
    pkcs8: Vec<u8>,
}

/// DER prefix of a P-256 SubjectPublicKeyInfo, followed by the 65-byte uncompressed point.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

impl DeviceKey {
    pub fn generate() -> Result<DeviceKey, String> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).map_err(|_| "could not create a key")?;
        DeviceKey::from_pkcs8(doc.as_ref().to_vec())
    }

    fn from_pkcs8(pkcs8: Vec<u8>) -> Result<DeviceKey, String> {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &SystemRandom::new())
            .map_err(|_| "private key is not EC P-256 in PKCS#8".to_string())?;
        Ok(DeviceKey { pair, pkcs8 })
    }

    /// Reads the key as stored in the config: PKCS#8 PEM.
    pub fn from_pem(pem: &str) -> Result<DeviceKey, String> {
        let der = pem_decode(pem, "PRIVATE KEY").ok_or("invalid private key PEM")?;
        DeviceKey::from_pkcs8(der)
    }

    pub fn to_pem(&self) -> String {
        pem_encode("PRIVATE KEY", &self.pkcs8)
    }

    /// Base64 SubjectPublicKeyInfo DER, sent at pairing time.
    pub fn public_spki(&self) -> String {
        let mut der = P256_SPKI_PREFIX.to_vec();
        der.extend_from_slice(self.pair.public_key().as_ref());
        B64.encode(der)
    }

    /// Base64 DER ECDSA-SHA256 signature over `msg`.
    pub fn sign(&self, msg: &str) -> Result<String, String> {
        let sig = self.pair.sign(&SystemRandom::new(), msg.as_bytes()).map_err(|_| "signing failed")?;
        Ok(B64.encode(sig.as_ref()))
    }
}

pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let b = B64.encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for chunk in b.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

/// Returns the DER of the first PEM block with this label.
pub fn pem_decode(pem: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin)? + begin.len();
    let stop = start + pem[start..].find(&end)?;
    let body: String = pem[start..stop].chars().filter(|c| !c.is_whitespace()).collect();
    B64.decode(body).ok()
}

/// Mirrors the server limit (10 SMS segments).
pub const MAX_BODY: usize = 1600;

/// E.164: a plus, a non-zero digit, then 6 to 14 digits.
pub fn is_e164(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 8 && b.len() <= 16 && b[0] == b'+' && (b'1'..=b'9').contains(&b[1]) && b[2..].iter().all(|c| c.is_ascii_digit())
}

/// The same checks as the server, as defence in depth.
pub fn validate_params(p: Option<&CommandParams>) -> Result<(), String> {
    let p = p.ok_or("missing params")?;
    if !is_e164(&p.to) {
        return Err(format!("recipient {:?} is not E.164", p.to));
    }
    let n = p.body.chars().count();
    if n == 0 || n > MAX_BODY || p.body.trim().is_empty() {
        return Err(format!("body must be 1-{MAX_BODY} characters"));
    }
    Ok(())
}

/// Uppercases, strips separators and fixes ambiguous letters, like the server.
pub fn normalize_pairing_code(s: &str) -> String {
    s.to_uppercase()
        .chars()
        .filter(|c| *c != '-' && *c != ' ')
        .map(|c| match c {
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        })
        .collect()
}

/// Strips spaces, dots, dashes and brackets and turns a leading 00 into +, like the server.
pub fn normalize_phone(s: &str) -> String {
    let s: String = s.trim().chars().filter(|c| !matches!(c, ' ' | '(' | ')' | '.' | '-' | '\t')).collect();
    match s.strip_prefix("00") {
        Some(rest) => format!("+{rest}"),
        None => s,
    }
}

/// GSM 03.38 basic set plus the extension table, as the server counts it.
const GSM7: &str =
    "\n\r !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}~£¥èéùìòÇØøÅåΔΦΓΛΩΠΨΣΘΞÆæßÉ¤¡ÄÖÑÜ§¿äöñüà€";

/// How many SMS a text needs (GSM-7: 160/153, otherwise UCS-2: 70/67).
pub fn segments(body: &str) -> i64 {
    let n = body.chars().count() as i64;
    if body.chars().all(|c| GSM7.contains(c)) {
        if n <= 160 {
            1
        } else {
            (n + 152) / 153
        }
    } else if n <= 70 {
        1
    } else {
        (n + 66) / 67
    }
}

/// The keyed tag the server sees instead of a phone number. The key never leaves the Bridge,
/// so the server can tell repeat recipients apart but not who they are.
pub fn recipient_tag(key: &[u8], to: &str) -> String {
    crate::util::hmac_hex(key, format!("pocketwire-recipient-v1|{to}").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway key, used only here, written by the earlier Go Bridge (x509.MarshalPKCS8PrivateKey):
    // existing pairings must keep working.
    const GO_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzHw82FIY/gZTA3bt\nDK/g23kAV7AniPFmTAExBJV1L5yhRANCAAQ3Acyxy7mQt1uwfQfnA9leJTVbA/p/\nw45+QigJV9Upmd+ZIqLuLaSqUI1b0NlDUj3R0Www0JuN7TsN8S2y8DSK\n-----END PRIVATE KEY-----\n";
    const GO_SPKI: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENwHMscu5kLdbsH0H5wPZXiU1WwP6f8OOfkIoCVfVKZnfmSKi7i2kqlCNW9DZQ1I90dFsMNCbje07DfEtsvA0ig==";

    #[test]
    fn reads_keys_from_the_go_bridge() {
        let k = DeviceKey::from_pem(GO_KEY).unwrap();
        assert_eq!(k.public_spki(), GO_SPKI);
    }

    #[test]
    fn signatures_verify() {
        let k = DeviceKey::generate().unwrap();
        let k2 = DeviceKey::from_pem(&k.to_pem()).unwrap();
        assert_eq!(k.public_spki(), k2.public_spki());
        let msg = challenge_string("n0nce", "dev_1");
        assert_eq!(msg, "pocketwire-v1|n0nce|dev_1");
        let sig = B64.decode(k.sign(&msg).unwrap()).unwrap();
        let spki = B64.decode(k.public_spki()).unwrap();
        let pubkey = ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, &spki[26..]);
        pubkey.verify(msg.as_bytes(), &sig).unwrap();
    }

    #[test]
    fn checks_match_the_server() {
        assert!(is_e164("+48501234567"));
        for bad in ["48501234567", "+0123456789", "+12345", "+1234567890123456", "+48 501"] {
            assert!(!is_e164(bad), "{bad}");
        }
        let ok = CommandParams { to: "+48501234567".into(), body: "hi".into() };
        assert!(validate_params(Some(&ok)).is_ok());
        assert!(validate_params(Some(&CommandParams { body: "   ".into(), ..ok.clone() })).is_err());
        assert!(validate_params(Some(&CommandParams { body: "x".repeat(1601), ..ok.clone() })).is_err());
        assert!(validate_params(None).is_err());
        assert_eq!(normalize_phone(" 0048 (501) 234-567 "), "+48501234567");
        assert_eq!(normalize_pairing_code("k7q2-m9xd il o"), "K7Q2M9XD110");
    }

    #[test]
    fn segments_and_tags() {
        assert_eq!(segments("hi"), 1);
        assert_eq!(segments(&"a".repeat(160)), 1);
        assert_eq!(segments(&"a".repeat(161)), 2);
        assert_eq!(segments("€uro [x]"), 1);
        assert_eq!(segments(&"ż".repeat(70)), 1);
        assert_eq!(segments(&"ż".repeat(71)), 2);
        // Same value as the Go Bridge, so the server keeps seeing the same tags after an upgrade.
        assert_eq!(recipient_tag(b"k", "+48501234567"), "fd6f94341ed40a4f2630350b9c8c24c64fca4bde99934cba6e6373b90e6a25ef");
    }
}
