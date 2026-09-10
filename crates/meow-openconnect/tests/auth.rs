use meow_openconnect::auth::{authenticate, Credentials};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn credentials() -> Credentials {
    Credentials {
        username: "user<&".into(),
        password: "secret<&".into(),
        authgroup: Some("Engineering".into()),
    }
}

async fn request(stream: &mut DuplexStream) -> (String, String) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(stream.read_u8().await.unwrap());
    }
    let header = String::from_utf8(header).unwrap();
    let size: usize = header
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse()
        .unwrap();
    let mut body = vec![0; size];
    stream.read_exact(&mut body).await.unwrap();
    (header, String::from_utf8(body).unwrap())
}

async fn response(stream: &mut DuplexStream, body: &str) {
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn separate_forms_group_selection_opaque_cookie_and_buffered_tunnel_data() {
    let (client, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        let (_, body) = request(&mut server).await;
        assert!(body.contains("<group-select>Engineering</group-select>"));
        assert!(!body.contains("secret"));
        response(&mut server, r#"<!DOCTYPE config-auth SYSTEM "config-auth.dtd"><config-auth type="auth-request"><opaque><state value="a&amp;b"/></opaque><auth><form action="/auth" method="post"><select name="group_list"><option value="engineering">Engineering</option><option value="guest">Guest</option></select><input type="text" name="username"/></form></auth></config-auth>"#).await;
        let (header, body) = request(&mut server).await;
        assert!(header.starts_with("POST /auth HTTP/1.1"));
        let doc = roxmltree::Document::parse(&body).unwrap();
        let root = doc.root_element();
        assert_eq!(
            root.children()
                .find(|n| n.has_tag_name("group-select"))
                .unwrap()
                .text(),
            Some("engineering")
        );
        assert_eq!(
            root.descendants()
                .find(|n| n.has_tag_name("username"))
                .unwrap()
                .text(),
            Some("user<&")
        );
        assert_eq!(
            root.descendants()
                .find(|n| n.has_tag_name("state"))
                .unwrap()
                .attribute("value"),
            Some("a&b")
        );
        let form = r#"<config-auth type="auth-request"><auth><form action="/password"><input type="password" name="password"/><input type="hidden" name="csrf" value="csrf-value"/></form></auth></config-auth>"#;
        server.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: state=state-cookie; Secure\r\n\r\n").await.unwrap();
        for part in form.as_bytes().chunks(13) {
            server
                .write_all(format!("{:x}\r\n", part.len()).as_bytes())
                .await
                .unwrap();
            server.write_all(part).await.unwrap();
            server.write_all(b"\r\n").await.unwrap();
        }
        server.write_all(b"0\r\n\r\n").await.unwrap();
        let (header, body) = request(&mut server).await;
        assert!(header.contains("Cookie: state=state-cookie\r\n"));
        assert!(header.starts_with("POST /password HTTP/1.1"));
        let doc = roxmltree::Document::parse(&body).unwrap();
        assert_eq!(
            doc.descendants()
                .find(|n| n.has_tag_name("password"))
                .unwrap()
                .text(),
            Some("secret<&")
        );
        assert_eq!(
            doc.descendants()
                .find(|n| n.has_tag_name("csrf"))
                .unwrap()
                .text(),
            Some("csrf-value")
        );
        let body = r#"<config-auth type="complete"><auth id="success"/></config-auth>"#;
        server.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSet-Cookie: webvpn=session-secret; Secure; HttpOnly\r\n\r\n{body}BUFFERED", body.len()).as_bytes()).await.unwrap();
    });
    let (mut stream, cookie) = authenticate(client, "vpn.test:443", &credentials())
        .await
        .unwrap();
    assert_eq!(cookie, "session-secret");
    let mut tail = [0; 8];
    stream.read_exact(&mut tail).await.unwrap();
    assert_eq!(&tail, b"BUFFERED");
    peer.await.unwrap();
}

#[tokio::test]
async fn challenges_and_cross_origin_actions_never_receive_credentials() {
    for body in [
        r#"<config-auth type="auth-request"><auth><form action="https://other.test/"><input name="password" type="password"/></form></auth></config-auth>"#,
        r#"<config-auth type="auth-request"><auth><form action="//other.test/"><input name="password" type="password"/></form></auth></config-auth>"#,
        r#"<config-auth type="auth-request"><auth><form action="/"><input name="otp" type="password"/></form></auth></config-auth>"#,
        r#"<!DOCTYPE config-auth [<!ENTITY secret SYSTEM "file:///etc/passwd">]><config-auth type="complete"><session-token>&secret;</session-token></config-auth>"#,
        r#"<config-auth type="auth-request"><error>secret&lt;&amp;</error></config-auth>"#,
    ] {
        let (client, mut server) = tokio::io::duplex(8192);
        let peer = tokio::spawn(async move {
            request(&mut server).await;
            response(&mut server, body).await;
            let mut extra = Vec::new();
            server.read_to_end(&mut extra).await.unwrap();
            assert!(extra.is_empty());
        });
        let error = authenticate(client, "vpn.test", &credentials())
            .await
            .err()
            .unwrap();
        assert!(!error.to_string().contains("secret"));
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn repeated_password_form_is_not_retried() {
    let (client, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        let form = r#"<config-auth type="auth-request"><auth><form><input name="password" type="password"/></form></auth></config-auth>"#;
        request(&mut server).await;
        response(&mut server, form).await;
        request(&mut server).await;
        response(&mut server, form).await;
        let mut extra = Vec::new();
        server.read_to_end(&mut extra).await.unwrap();
        assert!(extra.is_empty());
    });
    let error = authenticate(client, "vpn.test", &credentials())
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    peer.await.unwrap();
}

#[tokio::test]
async fn authentication_http_framing_is_bounded_and_unambiguous() {
    for header in [
        "Content-Length: 65537\r\n",
        "Content-Length: 1\r\nContent-Length: 2\r\n",
        "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
        "Content-Encoding: gzip\r\nContent-Length: 0\r\n",
        "Transfer-Encoding: chunked\r\n\r\n10001\r\n",
    ] {
        let (client, mut server) = tokio::io::duplex(8192);
        let peer = tokio::spawn(async move {
            request(&mut server).await;
            server
                .write_all(format!("HTTP/1.1 200 OK\r\n{header}\r\n").as_bytes())
                .await
                .unwrap();
        });
        assert!(authenticate(client, "vpn.test", &credentials())
            .await
            .is_err());
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn form_entries_are_scoped_and_submission_keys_take_precedence() {
    use meow_openconnect::{
        auth::{authenticate_configured, AuthOptions, FormEntry},
        settings::ClientProfile,
    };
    let (client, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        request(&mut server).await;
        response(&mut server, r#"<config-auth type="auth-request"><auth id="mfa"><form action="/otp"><input name="username" type="text"/><input name="otp" type="password"/><select name="realm"><option value="corp">Corporate</option><option value="guest">Guest</option></select></form></auth></config-auth>"#).await;
        let (_, body) = request(&mut server).await;
        let doc = roxmltree::Document::parse(&body).unwrap();
        let field = |name| {
            doc.descendants()
                .find(|node| node.has_tag_name(name))
                .and_then(|node| node.text())
        };
        assert_eq!(field("username"), Some("user<&"));
        assert_eq!(field("otp"), Some("right<&"));
        assert_eq!(field("realm"), Some("corp"));
        assert!(!body.contains("wrong") && !body.contains("secret"));
        response(
            &mut server,
            r#"<config-auth type="complete"><session-token>fixture</session-token></config-auth>"#,
        )
        .await;
    });
    let entries = [
        ("other", "", "otp", "wrong-form"),
        ("mfa", "", "otp", "wrong-priority"),
        ("", "mfa:otp:3", "", "right<&"),
        ("mfa", "", "realm", "Corporate"),
    ]
    .into_iter()
    .map(|(form, key, name, value)| FormEntry {
        form_id: form.into(),
        submission_key: key.into(),
        name: name.into(),
        value: value.into(),
        promote: false,
    })
    .collect();
    let result = authenticate_configured(
        client,
        "vpn.test",
        &credentials(),
        &ClientProfile::default(),
        &AuthOptions {
            form_entries: entries,
            ..Default::default()
        },
        || async { unreachable!() },
    )
    .await
    .unwrap();
    assert_eq!(result.1, "fixture");
    peer.await.unwrap();
}

#[tokio::test]
async fn legacy_auth_reopens_tls_and_sends_urlencoded_fields() {
    use meow_openconnect::{
        auth::{authenticate_configured, AuthOptions},
        settings::ClientProfile,
    };
    let (client, mut server) = tokio::io::duplex(8192);
    let (next_client, mut next_server) = tokio::io::duplex(8192);
    let (tunnel, mut tunnel_server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        let (header, body) = request(&mut server).await;
        assert!(header.starts_with("GET / HTTP/1.1") && header.contains("Connection: close"));
        assert!(body.is_empty() && !header.contains("X-Transcend-Version"));
        response(&mut server, r#"<auth id="login"><form action="/legacy"><input name="username" type="text"/><input name="password" type="password"/></form></auth>"#).await;
        let (header, body) = request(&mut next_server).await;
        assert!(header.starts_with("POST /legacy HTTP/1.1"));
        assert!(header.contains("Content-Type: application/x-www-form-urlencoded"));
        let fields: std::collections::BTreeMap<_, _> =
            url::form_urlencoded::parse(body.as_bytes()).collect();
        assert_eq!(fields.get("username").map(AsRef::as_ref), Some("user<&"));
        assert_eq!(fields.get("password").map(AsRef::as_ref), Some("secret<&"));
        next_server
            .write_all(
                b"HTTP/1.1 200 OK\r\nSet-Cookie: webvpn=fixture\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        tunnel_server.write_all(b"ready").await.unwrap();
    });
    let mut connections = std::collections::VecDeque::from([next_client, tunnel]);
    let (mut stream, cookie) = authenticate_configured(
        client,
        "vpn.test",
        &credentials(),
        &ClientProfile::default(),
        &AuthOptions {
            http_keep_alive_disabled: true,
            xml_post_disabled: true,
            ..Default::default()
        },
        || std::future::ready(Ok(connections.pop_front().unwrap())),
    )
    .await
    .unwrap();
    assert!(connections.is_empty());
    assert_eq!(cookie, "fixture");
    let mut ready = [0; 5];
    stream.read_exact(&mut ready).await.unwrap();
    assert_eq!(&ready, b"ready");
    peer.await.unwrap();
}

#[tokio::test]
async fn disabled_password_auth_never_submits_a_form() {
    use meow_openconnect::{
        auth::{authenticate_configured, AuthOptions},
        settings::ClientProfile,
    };
    let (client, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        let (_, body) = request(&mut server).await;
        assert!(!body.contains("single-sign-on"));
        response(&mut server, r#"<config-auth type="auth-request"><auth><form><input name="username" type="text"/></form></auth></config-auth>"#).await;
        let mut extra = Vec::new();
        server.read_to_end(&mut extra).await.unwrap();
        assert!(extra.is_empty());
    });
    let result = authenticate_configured(
        client,
        "vpn.test",
        &credentials(),
        &ClientProfile::default(),
        &AuthOptions {
            password_authentication_disabled: true,
            external_auth_disabled: true,
            ..Default::default()
        },
        || async { unreachable!() },
    )
    .await;
    assert_eq!(
        result.err().unwrap().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    peer.await.unwrap();
}

#[tokio::test]
async fn oidc_token_is_sent_only_after_a_bearer_challenge() {
    use meow_openconnect::{
        auth::{authenticate_configured, AuthOptions},
        settings::ClientProfile,
        token::Token,
    };
    for challenge in [
        "Bearer realm=fixture",
        "Basic realm=\"fixture, Bearer pretend\"",
    ] {
        let (client, mut server) = tokio::io::duplex(8192);
        let peer = tokio::spawn(async move {
            let (header, _) = request(&mut server).await;
            assert!(!header.contains("Authorization"));
            server.write_all(format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
            if challenge.starts_with("Bearer") {
                let (header, _) = request(&mut server).await;
                assert!(header.contains("Authorization: Bearer fixture-token\r\n"));
                response(&mut server, r#"<config-auth type="complete"><session-token>fixture-cookie</session-token></config-auth>"#).await;
            } else {
                let mut extra = Vec::new();
                server.read_to_end(&mut extra).await.unwrap();
                assert!(extra.is_empty());
            }
        });
        let result = authenticate_configured(
            client,
            "vpn.test",
            &credentials(),
            &ClientProfile::default(),
            &AuthOptions {
                token: Some(Token {
                    mode: "oidc".into(),
                    secret: "fixture-token".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            || async { unreachable!() },
        )
        .await;
        assert_eq!(result.is_ok(), challenge.starts_with("Bearer"));
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn totp_answers_a_secondary_challenge_without_reusing_the_password() {
    use meow_openconnect::{
        auth::{authenticate_configured, AuthOptions},
        settings::ClientProfile,
        token::Token,
    };
    let (client, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        request(&mut server).await;
        response(&mut server, r#"<config-auth type="auth-request"><auth id="challenge"><form><input name="secondary_password" type="password"/></form></auth></config-auth>"#).await;
        let (_, body) = request(&mut server).await;
        let doc = roxmltree::Document::parse(&body).unwrap();
        let token = doc
            .descendants()
            .find(|node| node.has_tag_name("secondary_password"))
            .unwrap()
            .text()
            .unwrap();
        assert_eq!(token.len(), 8);
        assert!(token.bytes().all(|byte| byte.is_ascii_digit()));
        assert!(!body.contains("secret"));
        response(
            &mut server,
            r#"<config-auth type="complete"><session-token>fixture</session-token></config-auth>"#,
        )
        .await;
    });
    authenticate_configured(
        client,
        "vpn.test",
        &credentials(),
        &ClientProfile::default(),
        &AuthOptions {
            token: Some(Token {
                mode: "totp".into(),
                secret: "otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQ&digits=8".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
        || async { unreachable!() },
    )
    .await
    .unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn mca_signs_the_exact_challenge_and_echoes_opaque_state() {
    use meow_openconnect::auth::{
        authenticate_configured, AuthOptions, CertificateResponse, MultipleCertificate,
    };
    use meow_openconnect::settings::ClientProfile;
    const CHALLENGE: &str = r#"<config-auth type="auth-request"><opaque><nonce>fixed&amp;nonce</nonce></opaque><multiple-client-cert-request><hash-algorithm>sha256</hash-algorithm></multiple-client-cert-request></config-auth>"#;
    struct Signer;
    impl MultipleCertificate for Signer {
        fn sign(&self, hashes: &[&str], challenge: &[u8]) -> std::io::Result<CertificateResponse> {
            assert_eq!(hashes, ["sha256"]);
            assert_eq!(challenge, CHALLENGE.as_bytes());
            Ok(CertificateResponse {
                certificates_pkcs7: b"certificate-fixture".to_vec(),
                hash_algorithm: "sha256".into(),
                signature: b"signature-fixture".to_vec(),
            })
        }
    }
    let (client, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        let (_, body) = request(&mut server).await;
        assert!(body.contains("<auth-method>multiple-cert</auth-method>"));
        response(&mut server, CHALLENGE).await;
        let (_, body) = request(&mut server).await;
        let doc = roxmltree::Document::parse(&body).unwrap();
        let signature = doc
            .descendants()
            .find(|node| node.has_tag_name("client-cert-auth-signature"))
            .unwrap();
        assert_eq!(signature.attribute("hash-algorithm-chosen"), Some("sha256"));
        assert_eq!(signature.text(), Some("c2lnbmF0dXJlLWZpeHR1cmU="));
        assert!(body.contains("<nonce>fixed&amp;nonce</nonce>"));
        response(
            &mut server,
            r#"<config-auth type="complete"><session-token>fixture</session-token></config-auth>"#,
        )
        .await;
    });
    authenticate_configured(
        client,
        "vpn.test",
        &credentials(),
        &ClientProfile::default(),
        &AuthOptions {
            mca: Some(std::sync::Arc::new(Signer)),
            ..Default::default()
        },
        || async { unreachable!() },
    )
    .await
    .unwrap();
    peer.await.unwrap();
}
