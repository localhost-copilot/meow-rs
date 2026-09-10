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
