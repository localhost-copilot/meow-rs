use std::collections::HashMap;

fn node(extra: &str) -> HashMap<String, serde_yaml::Value> {
    serde_yaml::from_str(&format!(
        "name: vpn\ntype: openconnect\nserver: vpn.example\ncookie: fixture-secret\n{extra}"
    ))
    .unwrap()
}

#[cfg(not(feature = "openconnect"))]
#[test]
fn disabled_feature_explains_how_to_enable_outbound() {
    let error = meow_config::proxy_parser::parse_proxy(&node(""), false)
        .err()
        .unwrap();
    assert!(error.contains("openconnect") && error.contains("feature"));
}

#[cfg(feature = "openconnect")]
#[test]
fn invalid_or_unimplemented_options_are_not_silently_accepted() {
    for extra in [
        "port: 0",
        "port: 65536",
        "mtu: 575",
        "handshake-timeout: 0",
        "handshake-timeout: 301",
        "dtls-mode: invalid",
        "protocol: f5",
        "compression: all",
        "ipv6-disabled: false\nmtu: 1200",
        "remote-dns-resolve: true\ndns: [not-an-ip]",
        "dialer-proxy: another",
        "username: user",
        "udp: definitely-not-a-boolean",
        "unexpected: option",
    ] {
        let result = meow_config::proxy_parser::parse_proxy(&node(extra), false);
        assert!(
            result.is_err(),
            "accepted unsupported/invalid option: {extra}"
        );
    }
    let mut invalid = node("");
    invalid.insert("cookie".into(), "fixture-secret\r\nInjected: true".into());
    let error = meow_config::proxy_parser::parse_proxy(&invalid, false)
        .err()
        .unwrap();
    assert!(!error.contains("fixture-secret"));
    assert!(meow_config::proxy_parser::parse_proxy(
        &node("dtls-mode: off\nipv6-disabled: true"),
        false
    )
    .is_ok());
}

#[cfg(feature = "openconnect")]
#[test]
fn dtls_modes_require_the_backend_feature() {
    for mode in ["auto", "require"] {
        let result =
            meow_config::proxy_parser::parse_proxy(&node(&format!("dtls-mode: {mode}")), false);
        assert_eq!(
            result.is_ok(),
            cfg!(all(feature = "openconnect-dtls", unix))
        );
        if let Err(error) = result {
            assert!(error.contains("openconnect-dtls"));
        }
    }
}
