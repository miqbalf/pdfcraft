//! Timestamp authorities for the seal worker: [`HttpTsa`] asks a remote RFC 3161 authority over
//! HTTP; [`DevTsa`] (`--insecure-dev-tsa`) answers in the process, for tests and throwaway stacks.
//!
//! Only the request `pdfcraft_sign` builds leaves the worker: the SHA-256 imprint of the
//! signature, never the document.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pdfcraft_sign::der;
use pdfcraft_sign::timestamp::{TimestampIssuance, TimestampSigner, parse_request, respond};
use pdfcraft_sign::{Certificate, DigestAlg, Name, PrivateKey, SignError, Time, TimestampAuthority};

/// How long one call to the authority may take, connect included.
pub const TIMEOUT: Duration = Duration::from_secs(15);
/// The largest reply taken from an authority.
pub const MAX_REPLY: u64 = 64 * 1024;
/// The longest `tsa_url` accepted.
const MAX_URL: usize = 2048;

/// Whether `url` may be given to [`HttpTsa`]: `https://` with a host and no user name or
/// password, or `http://` too when `allow_http` (`--insecure-dev`).
pub fn url_allowed(url: &str, allow_http: bool) -> bool {
    if url.len() > MAX_URL || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Ok(uri) = url.parse::<ureq::http::Uri>() else { return false };
    let scheme_ok = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => allow_http,
        _ => false,
    };
    let authority_ok = uri.authority().is_some_and(|a| !a.host().is_empty() && !a.as_str().contains('@'));
    scheme_ok && authority_ok
}

fn unavailable(why: &str) -> SignError {
    // The authority's own words never reach the wire: the seal maps any error here to
    // `tsa_unavailable` with a fixed sentence.
    SignError::Pdf(format!("timestamp authority: {why}"))
}

/// A remote RFC 3161 authority (`POST application/timestamp-query`).
pub struct HttpTsa {
    url: String,
    agent: ureq::Agent,
}

impl HttpTsa {
    /// An authority at `url` ([`url_allowed`] already checked), each call capped at `timeout`.
    pub fn new(url: &str, timeout: Duration) -> Self {
        let tls = ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build();
        let agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .build()
            .new_agent();
        HttpTsa { url: url.to_string(), agent }
    }
}

impl TimestampAuthority for HttpTsa {
    /// Connect failures, timeouts, any status but 200 and a reply over [`MAX_REPLY`] are errors,
    /// so the seal fails with `tsa_unavailable` and nothing is written.
    fn timestamp(&self, request: &[u8]) -> Result<Vec<u8>, SignError> {
        let mut reply = self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/timestamp-query")
            .header("Accept", "application/timestamp-reply")
            .send(request)
            .map_err(|_| unavailable("no answer"))?;
        if reply.status().as_u16() != 200 {
            return Err(unavailable("refused"));
        }
        // ureq refuses a body that reaches its limit, so one past the cap lets the cap itself in.
        reply.body_mut().with_config().limit(MAX_REPLY + 1).read_to_vec().map_err(|_| unavailable("no complete answer"))
    }
}

/// The in-process test authority (`--insecure-dev-tsa`): a P-256 key and a self-made
/// timestamping certificate, both made at start and never stored. Its tokens are real RFC 3161
/// tokens, but nothing trusts its certificate.
pub struct DevTsa {
    key: PrivateKey,
    certificate: Certificate,
    serial: AtomicU64,
}

/// `secs` since the epoch as an ASN.1 time.
fn time_at(secs: i64) -> Option<Time> {
    use chrono::{Datelike, Timelike};
    let t = chrono::DateTime::from_timestamp(secs, 0)?;
    Some(Time { year: u32::try_from(t.year()).ok()?, month: t.month(), day: t.day(), hour: t.hour(), minute: t.minute(), second: t.second() })
}

/// Seconds since the epoch, by the system clock.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

impl DevTsa {
    pub fn new() -> Result<Self, SignError> {
        let key = PrivateKey::generate_p256()?;
        let name = Name::build("PdfCraft seal-worker test timestamps (insecure)", "", "PdfCraft", "", "");
        let alg = key.preferred_digest();
        let sig_alg = key.signature_algorithm(alg);
        let bad_time = || SignError::Crypto("the clock is out of range".into());
        let from = time_at(now_secs() - 86_400).ok_or_else(bad_time)?;
        let until = Time { year: from.year + 10, ..from };
        // extKeyUsage, critical: id-kp-timeStamping only (RFC 3161 §2.3).
        let eku = der::seq(&[&der::oid("2.5.29.37"), &der::boolean(true), &der::octets(&der::seq(&[&der::oid("1.3.6.1.5.5.7.3.8")]))]);
        let tbs = der::seq(&[
            &der::explicit(0, &der::int(2)),
            &der::uint(&[0x01]),
            &sig_alg,
            &name.raw,
            &der::seq(&[&from.encode(), &until.encode()]),
            &name.raw,
            &key.public_key().spki(),
            &der::explicit(3, &der::seq(&[&eku])),
        ]);
        let signature = key.sign(alg, &tbs)?;
        let certificate = Certificate::parse(&der::seq(&[&tbs, &sig_alg, &der::bit_string(&signature)]))?;
        Ok(DevTsa { key, certificate, serial: AtomicU64::new(1) })
    }
}

impl TimestampAuthority for DevTsa {
    fn timestamp(&self, request: &[u8]) -> Result<Vec<u8>, SignError> {
        let query = parse_request(request)?;
        let generation_time = time_at(now_secs()).ok_or_else(|| SignError::Crypto("the clock is out of range".into()))?;
        respond(
            TimestampSigner { key: &self.key, certificate: &self.certificate, chain: &[], digest: DigestAlg::Sha256 },
            TimestampIssuance {
                query: &query,
                // An OID under the "example" arc of the test authority: no real policy.
                policy: "1.2.3.4",
                generation_time,
                serial: self.serial.fetch_add(1, Ordering::Relaxed),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    /// A one-shot HTTP server on loopback that reads the request and answers with `reply`
    /// after `delay`. Its URL.
    fn fake(reply: Vec<u8>, delay: Duration) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                thread::sleep(delay);
                let _ = s.write_all(&reply);
            }
        });
        format!("http://127.0.0.1:{port}/tsr")
    }

    fn reply(status: &str, body: &[u8]) -> Vec<u8> {
        let mut r =
            format!("HTTP/1.1 {status}\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
                .into_bytes();
        r.extend_from_slice(body);
        r
    }

    #[test]
    fn a_200_reply_within_the_cap_is_passed_on() {
        let url = fake(reply("200 OK", b"token"), Duration::ZERO);
        assert_eq!(HttpTsa::new(&url, TIMEOUT).timestamp(b"q").expect("answers"), b"token");
    }

    #[test]
    fn connect_failure_is_an_error() {
        // Bound and dropped: nothing listens there any more.
        let port = TcpListener::bind("127.0.0.1:0").expect("binds").local_addr().expect("addr").port();
        assert!(HttpTsa::new(&format!("http://127.0.0.1:{port}/tsr"), TIMEOUT).timestamp(b"q").is_err());
    }

    #[test]
    fn a_slow_authority_is_an_error() {
        let url = fake(reply("200 OK", b"token"), Duration::from_secs(3));
        assert!(HttpTsa::new(&url, Duration::from_millis(500)).timestamp(b"q").is_err());
    }

    #[test]
    fn a_status_other_than_200_is_an_error() {
        for status in ["500 Internal Server Error", "302 Found", "204 No Content"] {
            let url = fake(reply(status, b""), Duration::ZERO);
            assert!(HttpTsa::new(&url, TIMEOUT).timestamp(b"q").is_err(), "{status}");
        }
    }

    #[test]
    fn a_reply_over_the_cap_is_an_error() {
        let at_cap = fake(reply("200 OK", &vec![0x30; MAX_REPLY as usize]), Duration::ZERO);
        assert!(HttpTsa::new(&at_cap, TIMEOUT).timestamp(b"q").is_ok(), "the cap itself is allowed");
        let over = fake(reply("200 OK", &vec![0x30; MAX_REPLY as usize + 1]), Duration::ZERO);
        assert!(HttpTsa::new(&over, TIMEOUT).timestamp(b"q").is_err());
    }

    #[test]
    fn only_https_unless_insecure_dev() {
        assert!(url_allowed("https://freetsa.org/tsr", false));
        assert!(!url_allowed("http://freetsa.org/tsr", false));
        assert!(url_allowed("http://freetsa.org/tsr", true));
        for bad in ["ftp://x/tsr", "https://user:pw@x/tsr", "freetsa.org/tsr", "https:///tsr", "https://x/ tsr", ""] {
            assert!(!url_allowed(bad, true), "{bad}");
        }
    }

    #[test]
    fn dev_tsa_answers_a_query_with_a_token_for_its_imprint() {
        let tsa = DevTsa::new().expect("makes its key");
        let q = pdfcraft_sign::TimestampQuery::new(DigestAlg::Sha256, DigestAlg::Sha256.digest(&[b"x"])).expect("query");
        let reply = tsa.timestamp(&q.encode().expect("encodes")).expect("answers");
        let token = pdfcraft_sign::timestamp::parse_response(&reply, &q).expect("a token for this query");
        assert_eq!(token.imprint, q.imprint);
    }
}
