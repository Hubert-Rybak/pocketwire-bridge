//! The certificate for the Bridge's relay host name. By default it comes from Let's Encrypt
//! with the TLS-ALPN-01 challenge, which arrives through the tunnel like any other connection;
//! the private key is created and kept on this computer. The cache in `certs/` uses the same
//! files as the Go Bridge (golang.org/x/crypto/acme/autocert), so an upgrade keeps them.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;

use crate::logf;
use crate::util;

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
const ACME_ALPN: &[u8] = b"acme-tls/1";
/// Renew this long before a certificate expires (autocert's default).
const RENEW_BEFORE_MS: i64 = 30 * 24 * 3600 * 1000;

pub struct Certs {
    /// Caches the ACME account and certificates.
    pub dir: PathBuf,
    /// The ACME directory (default: Let's Encrypt production).
    pub directory_url: String,
    /// A fixed certificate instead of ACME (development and tests).
    fixed: Option<Arc<ServerConfig>>,
    hostname: Mutex<String>,
    current: Mutex<Option<(Arc<CertifiedKey>, i64, String)>>,
    challenges: Mutex<HashMap<String, Arc<CertifiedKey>>>,
    issuing: tokio::sync::Mutex<()>,
}

fn server_config(key: Arc<CertifiedKey>, alpn: &[u8]) -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(Fixed(key)));
    cfg.alpn_protocols = vec![alpn.to_vec()];
    Arc::new(cfg)
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl rustls::server::ResolvesServerCert for Fixed {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn certified(certs: Vec<CertificateDer<'static>>, key: &PrivateKeyDer<'_>) -> Result<Arc<CertifiedKey>, String> {
    if certs.is_empty() {
        return Err("no certificate".into());
    }
    let signer = rustls::crypto::ring::sign::any_supported_type(key).map_err(|e| e.to_string())?;
    Ok(Arc::new(CertifiedKey::new(certs, signer)))
}

/// Reads a PEM bundle: a private key and the certificate chain, in any order.
fn parse_bundle(pem: &[u8]) -> Result<(Arc<CertifiedKey>, i64), String> {
    let key = PrivateKeyDer::from_pem_slice(pem).map_err(|e| format!("private key: {e:?}"))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem).filter_map(Result::ok).collect();
    let not_after = certs.first().and_then(|c| crate::der::not_after_ms(c)).unwrap_or(0);
    Ok((certified(certs, &key)?, not_after))
}

impl Certs {
    pub fn new(dir: PathBuf, directory_url: Option<String>, cert_file: Option<String>, key_file: Option<String>) -> Result<Arc<Certs>, String> {
        let fixed = match (cert_file, key_file) {
            (Some(c), Some(k)) if !c.is_empty() && !k.is_empty() => {
                let mut pem = std::fs::read(&c).map_err(|e| format!("{c}: {e}"))?;
                pem.extend(std::fs::read(&k).map_err(|e| format!("{k}: {e}"))?);
                let (ck, _) = parse_bundle(&pem)?;
                Some(server_config(ck, b"http/1.1"))
            }
            _ => None,
        };
        Ok(Arc::new(Certs {
            dir,
            directory_url: directory_url.filter(|s| !s.is_empty()).unwrap_or_else(|| LETS_ENCRYPT.into()),
            fixed,
            hostname: Mutex::new(String::new()),
            current: Mutex::new(None),
            challenges: Mutex::new(HashMap::new()),
            issuing: tokio::sync::Mutex::new(()),
        }))
    }

    /// Records the host name the relay assigned; certificates are issued only for it.
    pub fn set_hostname(&self, h: &str) {
        *self.hostname.lock().unwrap() = h.to_string();
    }

    pub fn hostname(&self) -> String {
        self.hostname.lock().unwrap().clone()
    }

    /// The TLS configuration for a connection, from its ClientHello. HTTP/2 is not offered.
    pub async fn config_for(self: &Arc<Self>, sni: Option<&str>, alpn: &[Vec<u8>]) -> Result<Arc<ServerConfig>, String> {
        if let Some(cfg) = &self.fixed {
            return Ok(cfg.clone());
        }
        let host = self.hostname();
        let sni = sni.unwrap_or("");
        if host.is_empty() || !sni.eq_ignore_ascii_case(&host) {
            return Err("not this Bridge's host name".into());
        }
        if alpn.iter().any(|p| p == ACME_ALPN) {
            let ck = self.challenges.lock().unwrap().get(&host).cloned().ok_or("no pending ACME challenge")?;
            return Ok(server_config(ck, ACME_ALPN));
        }
        Ok(server_config(self.certificate(&host).await?, b"http/1.1"))
    }

    /// The certificate for `host`: from memory, the cache, or a new one from the ACME CA.
    async fn certificate(self: &Arc<Self>, host: &str) -> Result<Arc<CertifiedKey>, String> {
        let now = util::now_ms();
        if let Some((ck, exp, h)) = self.current.lock().unwrap().clone() {
            if h == host && now < exp {
                if exp - now < RENEW_BEFORE_MS {
                    self.renew_in_background(host);
                }
                return Ok(ck);
            }
        }
        let _g = self.issuing.lock().await;
        if let Ok(pem) = std::fs::read(self.dir.join(host)) {
            if let Ok((ck, exp)) = parse_bundle(&pem) {
                if now < exp {
                    *self.current.lock().unwrap() = Some((ck.clone(), exp, host.to_string()));
                    if exp - now < RENEW_BEFORE_MS {
                        drop(_g);
                        self.renew_in_background(host);
                    }
                    return Ok(ck);
                }
            }
        }
        self.issue(host).await
    }

    fn renew_in_background(self: &Arc<Self>, host: &str) {
        let me = self.clone();
        let host = host.to_string();
        tokio::spawn(async move {
            let Ok(_g) = me.issuing.try_lock() else { return };
            if let Err(e) = me.issue(&host).await {
                logf!("renewing the relay certificate failed: {e}");
            }
        });
    }

    fn account_key(&self) -> Result<PrivatePkcs8KeyDer<'static>, String> {
        let path = self.dir.join("acme_account+key");
        if let Ok(pem) = std::fs::read(&path) {
            match PrivateKeyDer::from_pem_slice(&pem) {
                Ok(PrivateKeyDer::Pkcs8(k)) => return Ok(k),
                Ok(PrivateKeyDer::Sec1(k)) => {
                    if let Some(p8) = crate::der::sec1_p256_to_pkcs8(k.secret_sec1_der()) {
                        return Ok(PrivatePkcs8KeyDer::from(p8));
                    }
                }
                _ => {}
            }
        }
        let kp = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
        crate::config::create_private_dir(&self.dir)?;
        crate::config::write_private(&path, kp.serialize_pem().as_bytes())?;
        Ok(PrivatePkcs8KeyDer::from(kp.serialize_der()))
    }

    async fn issue(self: &Arc<Self>, host: &str) -> Result<Arc<CertifiedKey>, String> {
        use instant_acme::{Account, ChallengeType, Identifier, Key, NewOrder, OrderStatus, RetryPolicy};
        logf!("getting a certificate for {host} from {}", self.directory_url);
        let err = |e: instant_acme::Error| e.to_string();
        let pkcs8 = self.account_key()?;
        let key = Key::from_pkcs8_der(PrivatePkcs8KeyDer::from(pkcs8.secret_pkcs8_der().to_vec())).map_err(err)?;
        let (account, _) = Account::builder_with_http(Box::new(AcmeHttp))
            .create_from_key((key, PrivateKeyDer::Pkcs8(pkcs8)), self.directory_url.clone())
            .await
            .map_err(err)?;
        let ids = [Identifier::Dns(host.to_string())];
        let mut order = account.new_order(&NewOrder::new(&ids)).await.map_err(err)?;
        {
            let mut auths = order.authorizations();
            while let Some(a) = auths.next().await {
                let mut a = a.map_err(err)?;
                if matches!(a.status, instant_acme::AuthorizationStatus::Valid) {
                    continue;
                }
                let mut ch = a.challenge(ChallengeType::TlsAlpn01).ok_or("the CA offered no tls-alpn-01 challenge")?;
                let digest = ch.key_authorization().digest().as_ref().to_vec();
                let kp = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
                let mut params = rcgen::CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
                params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(&digest)];
                let cert = params.self_signed(&kp).map_err(|e| e.to_string())?;
                let ck = certified(vec![cert.der().clone()], &PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der())))?;
                self.challenges.lock().unwrap().insert(host.to_string(), ck);
                ch.set_ready().await.map_err(err)?;
            }
        }
        let retry = RetryPolicy::new().timeout(Duration::from_secs(90));
        let status = order.poll_ready(&retry).await.map_err(err);
        self.challenges.lock().unwrap().remove(host);
        let status = status?;
        if status != OrderStatus::Ready {
            return Err(format!("the CA did not accept the challenge (order {status:?})"));
        }
        let kp = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&kp).map_err(|e| e.to_string())?;
        order.finalize_csr(csr.der()).await.map_err(err)?;
        let chain = order.poll_certificate(&retry).await.map_err(err)?;
        let bundle = format!("{}{}", kp.serialize_pem(), chain);
        let (ck, exp) = parse_bundle(bundle.as_bytes())?;
        crate::config::create_private_dir(&self.dir)?;
        crate::config::write_private(&self.dir.join(host), bundle.as_bytes())?;
        *self.current.lock().unwrap() = Some((ck.clone(), exp, host.to_string()));
        logf!("got a certificate for {host}, valid until {}", util::rfc3339(exp, false));
        Ok(ck)
    }
}

/// instant-acme's HTTP client, over the Bridge's own (proxy-aware) requests.
struct AcmeHttp;

impl instant_acme::HttpClient for AcmeHttp {
    fn request(
        &self,
        req: http::Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>> {
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            let headers: Vec<(&str, String)> = parts.headers.iter().filter_map(|(k, v)| Some((k.as_str(), v.to_str().ok()?.to_string()))).collect();
            let res = crate::net::request(parts.method.as_str(), &parts.uri.to_string(), &headers, body, 1 << 20)
                .await
                .map_err(|e| instant_acme::Error::Other(e.into()))?;
            let mut out = http::Response::new(Full::new(res.body));
            *out.status_mut() = http::StatusCode::from_u16(res.status).unwrap_or(http::StatusCode::BAD_GATEWAY);
            *out.headers_mut() = res.headers;
            Ok(instant_acme::BytesResponse::from(out))
        })
    }
}
