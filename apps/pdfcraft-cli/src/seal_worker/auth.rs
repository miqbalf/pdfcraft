//! The seal worker's request and reply MACs, the nonce cache and the seal rate limit.
//!
//! Every request carries `X-Craft-Seal-Time` (unix seconds), `X-Craft-Seal-Nonce` (32 lowercase
//! hex) and `X-Craft-Seal-Mac`, the lowercase hex of
//! `HMAC-SHA256(secret, METHOD "\n" PATH "\n" hex(sha256(body)) "\n" time "\n" nonce)`. Every reply
//! carries `X-Craft-Seal-Reply = hex(HMAC-SHA256(secret, "reply\n" request_mac "\n" hex(sha256(reply_body))))`.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// A request's time may differ from the worker's clock by at most this many seconds.
pub const MAX_SKEW_SECS: i64 = 60;
/// A nonce is refused when it was seen this recently: longer than any one request time can be
/// accepted (2 × [`MAX_SKEW_SECS`], plus a second for the clock floored to the second; P5 review m1).
pub const NONCE_WINDOW: Duration = Duration::from_secs(2 * MAX_SKEW_SECS as u64 + 2);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn mac(secret: &[u8], parts: &[&[u8]]) -> Option<HmacSha256> {
    let mut m = HmacSha256::new_from_slice(secret).ok()?;
    for p in parts {
        m.update(p);
    }
    Some(m)
}

/// The text a request MAC covers.
fn request_text(method: &str, path: &str, body: &[u8], time: &str, nonce: &str) -> String {
    format!("{method}\n{path}\n{}\n{time}\n{nonce}", sha256_hex(body))
}

/// The request MAC, lowercase hex (what a client sends; the worker only checks it).
#[cfg(test)]
pub fn request_mac(secret: &[u8], method: &str, path: &str, body: &[u8], time: &str, nonce: &str) -> String {
    mac(secret, &[request_text(method, path, body, time, nonce).as_bytes()]).map(|m| hex(&m.finalize().into_bytes())).unwrap_or_default()
}

/// The reply MAC for a reply `body` to the request whose MAC header was `request_mac`.
pub fn reply_mac(secret: &[u8], request_mac: &str, body: &[u8]) -> String {
    let text = format!("reply\n{request_mac}\n{}", sha256_hex(body));
    mac(secret, &[text.as_bytes()]).map(|m| hex(&m.finalize().into_bytes())).unwrap_or_default()
}

/// 32 lowercase hex digits.
fn is_nonce(n: &str) -> bool {
    n.len() == 32 && n.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// `s` as bytes when it is 64 lowercase hex digits (a SHA-256 MAC).
fn mac_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() != 64 || !s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..32).map(|i| s.get(i * 2..i * 2 + 2).and_then(|p| u8::from_str_radix(p, 16).ok())).collect()
}

/// One request as its MAC covers it: method, path and body, and its authentication headers.
#[derive(Clone, Copy)]
pub struct Presented<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
    pub time: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub mac: Option<&'a str>,
}

/// Recently seen nonces.
#[derive(Default)]
pub struct NonceCache {
    seen: HashMap<String, Instant>,
}

impl NonceCache {
    /// Record `nonce` at `now`; false when it was already seen within [`NONCE_WINDOW`].
    pub fn insert(&mut self, nonce: &str, now: Instant) -> bool {
        self.seen.retain(|_, at| now.saturating_duration_since(*at) < NONCE_WINDOW);
        if self.seen.contains_key(nonce) {
            return false;
        }
        self.seen.insert(nonce.to_string(), now);
        true
    }
}

/// Whether the request is authentic: its time within [`MAX_SKEW_SECS`] of `now_unix`, its MAC
/// right (compared in constant time) and its nonce unseen. The nonce is recorded only for a
/// request whose MAC is right, so forged requests cannot fill the cache.
pub fn verify(secret: &[u8], h: &Presented<'_>, now_unix: i64, nonces: &mut NonceCache, now: Instant) -> bool {
    let (Some(time), Some(nonce), Some(given)) = (h.time, h.nonce, h.mac) else { return false };
    let Ok(t) = time.parse::<i64>() else { return false };
    if !time.bytes().all(|c| c.is_ascii_digit()) || (now_unix - t).abs() > MAX_SKEW_SECS || !is_nonce(nonce) {
        return false;
    }
    let Some(given) = mac_bytes(given) else { return false };
    let Some(m) = mac(secret, &[request_text(h.method, h.path, h.body, time, nonce).as_bytes()]) else { return false };
    if m.verify_slice(&given).is_err() {
        return false;
    }
    nonces.insert(nonce, now)
}

/// At most `max` events in any `window`.
pub struct RateLimit {
    max: usize,
    window: Duration,
    recent: VecDeque<Instant>,
}

impl RateLimit {
    pub fn new(max: usize, window: Duration) -> Self {
        RateLimit { max, window, recent: VecDeque::new() }
    }

    /// Count one event at `now`; false (and not counted) when the window is full.
    pub fn allow(&mut self, now: Instant) -> bool {
        while self.recent.front().is_some_and(|t| now.saturating_duration_since(*t) >= self.window) {
            self.recent.pop_front();
        }
        if self.recent.len() >= self.max {
            return false;
        }
        self.recent.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret-for-vectors";
    const TIME: &str = "1700000000";
    const NONCE: &str = "00112233445566778899aabbccddeeff";

    /// The vectors N3's `SealClientTest::test_literal_mac_vectors_shared_with_the_worker_lane`
    /// checks on the PHP side (computed there independently with Python's hmac).
    #[test]
    fn mac_vectors_shared_with_the_php_client() {
        let get = request_mac(SECRET, "GET", "/v1/health", b"", TIME, NONCE);
        assert_eq!(get, "17ce09fa7ea52f63effdfb69ebb88bdebe5de9d98a2729442aa18578671fc6f1");
        assert_eq!(reply_mac(SECRET, &get, br#"{"ok":true}"#), "62b218ec3671185a5c464515c08c88d319c187c779297c7c0713d36fda7fd2e3");
        let post = request_mac(SECRET, "POST", "/v1/inspect", br#"{"pdf":"JVBERi0="}"#, TIME, NONCE);
        assert_eq!(post, "0a33c7ac015789582747c242c5d6086a39da3813631b2192351ff968212d2ff5");
    }

    #[test]
    fn verify_accepts_the_vector_once_and_refuses_a_change() {
        let now = Instant::now();
        let mac = request_mac(SECRET, "GET", "/v1/health", b"", TIME, NONCE);
        let h = Presented { method: "GET", path: "/v1/health", body: b"", time: Some(TIME), nonce: Some(NONCE), mac: Some(&mac) };
        let other = Presented { body: b"x", ..h };
        let mut cache = NonceCache::default();
        assert!(!verify(SECRET, &other, 1_700_000_000, &mut cache, now), "another body");
        assert!(!verify(SECRET, &h, 1_700_000_061, &mut cache, now), "too late");
        assert!(verify(SECRET, &h, 1_700_000_060, &mut cache, now), "within the skew");
        assert!(!verify(SECRET, &h, 1_700_000_000, &mut cache, now), "the nonce again");
        assert!(cache.insert(NONCE, now + NONCE_WINDOW), "forgotten after the window");
    }

    /// P5 review m1: a request up to MAX_SKEW_SECS ahead of the worker's clock is accepted for about
    /// 2 × MAX_SKEW_SECS + 1 s of real time (the clock is floored to the second), so its nonce is kept
    /// at least that long.
    #[test]
    fn a_nonce_is_kept_while_its_time_can_still_be_accepted() {
        let now = Instant::now();
        let ahead = 1_700_000_060; // the request's time: 60 s ahead of the worker
        let mac = request_mac(SECRET, "GET", "/v1/health", b"", "1700000060", NONCE);
        let h = Presented { method: "GET", path: "/v1/health", body: b"", time: Some("1700000060"), nonce: Some(NONCE), mac: Some(&mac) };
        let mut cache = NonceCache::default();
        // First accepted at real time 1_700_000_000.9 (floored to ..000), replayed at real time ..060.9
        // (floored to ..060, still within the skew): 120.x s later.
        assert!(verify(SECRET, &h, ahead - 60, &mut cache, now));
        let later = now + Duration::from_millis(121_900);
        assert!(!verify(SECRET, &h, ahead + 60, &mut cache, later), "replayed at the far edge of the skew");
        assert!(NONCE_WINDOW.as_secs() as i64 > 2 * MAX_SKEW_SECS + 1);
    }

    #[test]
    fn rate_limit_refuses_one_past_the_cap_then_recovers() {
        let mut r = RateLimit::new(30, Duration::from_secs(10));
        let t = Instant::now();
        assert!((0..30).all(|_| r.allow(t)));
        assert!(!r.allow(t + Duration::from_secs(9)));
        assert!(r.allow(t + Duration::from_secs(10)));
    }
}
