//! Shared SSRF / transport-safety host checks.
//!
//! These live outside the provider modules because all three providers need
//! them: Web Push validates an attacker-supplied subscription endpoint, while
//! FCM and APNS validate their (test-overridable) API base URLs so a
//! credential-bearing request can never be sent in the clear against a
//! non-loopback host.

/// True for hosts that name the local machine.
///
/// Loopback is exempt from the https + internal-target checks, but only when
/// the caller has explicitly opted in (see `allow_insecure_loopback` on each
/// provider config) — the exemption is for local stub/integration tests and
/// must not be reachable in a production binary.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Build a `reqwest::Client` carrying both an overall and a connect-phase
/// timeout.
///
/// FCM and APNS construct their HTTP client identically; this used to be an
/// 8-line block (including this same explanatory comment) duplicated
/// verbatim in both `fcm.rs` and `apns.rs`. `web_push.rs` does not use this:
/// it additionally needs `.redirect(Policy::none())` and, for a resolved
/// domain endpoint, `.resolve_to_addrs(..)` — configuration this helper
/// deliberately does not force onto FCM/APNS.
#[cfg(any(feature = "fcm", feature = "apns"))]
pub(crate) fn build_push_client(
    timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
) -> crate::Result<reqwest::Client> {
    // `.no_proxy()`: an ambient `HTTPS_PROXY` must not silently receive the
    // OAuth/JWT-bearing provider traffic; a proxy is used only if one is
    // configured explicitly (there is currently no such option).
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(connect_timeout)
        .no_proxy()
        .build()
        .map_err(|e| crate::PushError::Config(e.to_string()))
}

/// Address classification is shared with every other egress-guarded client
/// in the workspace via [`armature_http_client::egress`]: the full IANA
/// special-purpose registries for IPv4 and IPv6 (incl. `192.88.99.0/24`,
/// documentation ranges, `64:ff9b:1::/48`, `fec0::/10`, multicast) and every
/// IPv4-embedding IPv6 form (mapped, compatible, translated, NAT64, 6to4,
/// Teredo). Both functions include loopback; callers that permit loopback
/// under `allow_insecure_loopback` exempt it explicitly.
#[cfg(feature = "web-push")]
pub(crate) use armature_http_client::egress::{is_internal_v4, is_internal_v6};

/// A log-safe stand-in for a device token or subscription endpoint: the first
/// six characters and the length.
///
/// A device token (FCM registration token, APNS device token) or a Web Push
/// endpoint URL is a bearer capability: with the provider credentials it
/// addresses one user's device, and it identifies that device across apps
/// and logs. The prefix is enough to correlate log lines with a known token.
pub(crate) fn token_fingerprint(token: &str) -> String {
    let prefix: String = token.chars().take(6).collect();
    format!("{prefix}…(len {})", token.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_fingerprint_does_not_contain_the_token() {
        let token = "dQw4w9WgXcQ:APA91bHPRgkF3JUikC4ENAHEeMrd41Zxv3hVZjC9KtT8OvPVGJ";
        let fp = token_fingerprint(token);
        assert!(!fp.contains(token));
        assert!(fp.starts_with("dQw4w9"));
        assert!(fp.contains(&token.len().to_string()));
    }

    #[cfg(feature = "web-push")]
    #[test]
    fn shared_classifier_covers_the_ranges_push_relied_on() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let v4 = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        for ip in [
            "169.254.169.254",
            "10.0.0.1",
            "100.64.0.1",
            "0.1.2.3",
            "198.18.0.1",
        ] {
            assert!(is_internal_v4(&v4(ip)), "{ip}");
        }
        // Newly covered by the shared registry-based classifier.
        for ip in ["192.88.99.1", "192.0.2.1", "198.51.100.1", "203.0.113.1"] {
            assert!(is_internal_v4(&v4(ip)), "{ip}");
        }
        for ip in [
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2002:a9fe:a9fe::",
            "2001:0:4136:e378:8000:63bf:5601:5601",
            "::1",
            "ff02::1",
        ] {
            assert!(is_internal_v6(&v6(ip)), "{ip}");
        }
        assert!(!is_internal_v4(&v4("93.184.216.34")));
    }
}
