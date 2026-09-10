use std::collections::HashMap;

pub(super) fn parse(
    config: &HashMap<String, serde_yaml::Value>,
    dialer: &std::sync::Arc<dyn meow_proxy::dialer::TcpDialer>,
) -> std::result::Result<meow_proxy::openconnect_adapter::OpenConnectAdapter, String> {
    // Strict decoding prevents an unsupported authentication/DTLS setting from
    // being silently accepted while the node runs with different semantics.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    struct Options {
        name: String,
        #[serde(rename = "type")]
        _kind: String,
        server: String,
        port: Option<u16>,
        cookie: Option<String>,
        username: Option<String>,
        password: Option<String>,
        authgroup: Option<String>,
        protocol: Option<String>,
        server_name: Option<String>,
        ca: Option<String>,
        cert: Option<String>,
        key: Option<String>,
        key_password: Option<String>,
        mca_certificate: Option<String>,
        mca_key: Option<String>,
        mca_key_password: Option<String>,
        cert_expire_warning: Option<u32>,
        peer_fingerprint: Option<String>,
        peer_fingerprints: Option<Vec<String>>,
        system_trust_disabled: Option<bool>,
        skip_cert_verify: Option<bool>,
        pfs: Option<bool>,
        allow_insecure_crypto: Option<bool>,
        reported_os: Option<String>,
        user_agent: Option<String>,
        version: Option<String>,
        local_hostname: Option<String>,
        mobile: Option<meow_proxy::openconnect_adapter::Mobile>,
        form_entries: Option<Vec<meow_proxy::openconnect_adapter::FormEntry>>,
        http_keepalive_disabled: Option<bool>,
        xml_post_disabled: Option<bool>,
        external_auth_disabled: Option<bool>,
        password_authentication_disabled: Option<bool>,
        token_mode: Option<String>,
        token_secret: Option<String>,
        token_pin: Option<String>,
        token_password: Option<String>,
        token_device_id: Option<String>,
        token_counter: Option<u64>,
        mtu: Option<u16>,
        base_mtu: Option<u16>,
        dpd_interval: Option<u64>,
        queue_length: Option<usize>,
        handshake_timeout: Option<u64>,
        reconnect_timeout: Option<u64>,
        ipv6_disabled: Option<bool>,
        udp: Option<bool>,
        dtls_mode: Option<String>,
        dtls_key_exchange: Option<String>,
        legacy_dtls: Option<bool>,
        dtls_local_port: Option<u16>,
        compression: Option<String>,
        dialer_proxy: Option<String>,
        interface_name: Option<String>,
        routing_mark: Option<u32>,
        ip_version: Option<String>,
        tfo: Option<bool>,
        mptcp: Option<bool>,
        remote_dns_resolve: Option<bool>,
        dns: Option<Vec<String>>,
    }
    let value = serde_yaml::to_value(config)
        .map_err(|_| "openconnect: invalid configuration".to_owned())?;
    let options: Options =
        serde_yaml::from_value(value).map_err(|e| format!("openconnect: {e}"))?;
    if !matches!(options.protocol.as_deref().unwrap_or(""), "" | "anyconnect") {
        return Err("openconnect: only protocol: anyconnect is supported".into());
    }
    use meow_proxy::openconnect_adapter::DtlsMode;
    let default_dtls = if cfg!(all(feature = "openconnect-dtls", unix)) {
        "auto"
    } else {
        "off"
    };
    let dtls_mode = match options
        .dtls_mode
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(default_dtls)
    {
        "off" => DtlsMode::Off,
        "auto" => DtlsMode::Auto,
        "require" => DtlsMode::Require,
        _ => return Err("openconnect: dtls-mode must be off, auto or require".into()),
    };
    if dtls_mode != DtlsMode::Off && !cfg!(all(feature = "openconnect-dtls", unix)) {
        return Err(
            "openconnect: DTLS requires --features openconnect-dtls on a supported Unix platform"
                .into(),
        );
    }
    use meow_proxy::openconnect_adapter::Compression;
    let compression = match options.compression.as_deref().unwrap_or("stateless") {
        "off" => Compression::Off,
        "" | "stateless" => Compression::Stateless,
        "all" => Compression::All,
        _ => return Err("openconnect: compression must be off, stateless or all".into()),
    };
    // Registry resolution injects the named proxy after all outbounds are parsed.
    let _ = options.dialer_proxy;
    // The first version accepts a bare DNS name or IP literal, not a URL with
    // ambiguous group/path or port precedence. The CSTP endpoint path is fixed.
    if options.server.contains(['/', '@', '?', '#', '[', ']'])
        || (options.server.contains(':') && options.server.parse::<std::net::IpAddr>().is_err())
    {
        return Err(
            "openconnect: server must be a bare hostname or IP; use port separately".into(),
        );
    }
    fn material(value: Option<String>, name: &str) -> std::result::Result<Vec<u8>, String> {
        match value.filter(|value| !value.is_empty()) {
            Some(value) if value.contains("-----BEGIN ") => Ok(value.into_bytes()),
            Some(path) => {
                std::fs::read(path).map_err(|_| format!("openconnect: cannot read {name} file"))
            }
            None => Ok(Vec::new()),
        }
    }
    let pem = material(options.ca, "CA")?;
    let roots = if pem.is_empty() {
        Vec::new()
    } else {
        let roots = rustls_pemfile::certs(&mut pem.as_slice())
            .map(|cert| cert.map(|cert| cert.to_vec()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| "openconnect: invalid CA PEM".to_owned())?;
        if roots.is_empty() {
            return Err("openconnect: CA file contains no certificates".into());
        }
        roots
    };
    let cookie = options.cookie.filter(|value| !value.is_empty());
    let credentials = if cookie.is_some() {
        None
    } else {
        Some(meow_proxy::openconnect_adapter::Credentials {
            username: options.username.unwrap_or_default(),
            password: options.password.unwrap_or_default(),
            authgroup: options.authgroup.filter(|value| !value.is_empty()),
        })
    };
    let dns = options
        .dns
        .unwrap_or_default()
        .iter()
        .map(|server| {
            server
                .parse::<std::net::IpAddr>()
                .map(|ip| std::net::SocketAddr::new(ip, 53))
                .or_else(|_| server.parse::<std::net::SocketAddr>())
                .map_err(|_| {
                    "openconnect: DNS servers must be IP literals with optional ports".to_owned()
                })
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    use meow_proxy::openconnect_adapter::{
        AdvancedOptions, ClientProfile, ConnectSettings, TlsOptions,
    };
    let mut profile = ClientProfile::default();
    if let Some(value) = options.reported_os.filter(|value| !value.is_empty()) {
        profile.reported_os = value;
    }
    if let Some(value) = options.user_agent.filter(|value| !value.is_empty()) {
        profile.user_agent = value;
    }
    if let Some(value) = options.version.filter(|value| !value.is_empty()) {
        profile.version = value;
    }
    if let Some(hostname) = options.local_hostname.filter(|name| !name.is_empty()) {
        profile.local_hostname = hostname;
    }
    profile.mobile = options.mobile;
    if profile.mobile.is_none() && matches!(profile.reported_os.as_str(), "android" | "apple-ios") {
        profile.mobile = Some(meow_proxy::openconnect_adapter::Mobile {
            platform_version: "1.0".into(),
            device_type: profile.reported_os.clone(),
            device_unique_id: "A".repeat(40),
        });
    }
    let base_mtu = options.base_mtu.unwrap_or(0);
    if base_mtu != 0 && base_mtu < 576 {
        return Err("openconnect: base-mtu must be zero or between 576 and 65535".into());
    }
    let dtls_resumption_only = match options.dtls_key_exchange.as_deref().unwrap_or("auto") {
        "" | "auto" => false,
        "resumption" => true,
        _ => return Err("openconnect: dtls-key-exchange must be auto or resumption".into()),
    };
    let mut peer_fingerprints = options.peer_fingerprints.unwrap_or_default();
    if let Some(value) = options.peer_fingerprint.filter(|value| !value.is_empty()) {
        peer_fingerprints.push(value);
    }
    let token = if [
        &options.token_mode,
        &options.token_secret,
        &options.token_pin,
        &options.token_password,
        &options.token_device_id,
    ]
    .into_iter()
    .any(|value| value.as_ref().is_some_and(|value| !value.is_empty()))
        || options.token_counter.unwrap_or(0) != 0
    {
        Some(meow_proxy::openconnect_adapter::Token {
            mode: options.token_mode.unwrap_or_default(),
            secret: options.token_secret.unwrap_or_default(),
            pin: options.token_pin.unwrap_or_default(),
            password: options.token_password.unwrap_or_default(),
            device_id: options.token_device_id.unwrap_or_default(),
            counter: options.token_counter.unwrap_or_default(),
        })
    } else {
        None
    };
    use meow_proxy::openconnect_adapter::IpVersion;
    let ip_version = match options.ip_version.as_deref().unwrap_or("dual") {
        "" | "dual" => IpVersion::Dual,
        "ipv4" => IpVersion::Ipv4,
        "ipv6" => IpVersion::Ipv6,
        "ipv4-prefer" => IpVersion::Ipv4Prefer,
        "ipv6-prefer" => IpVersion::Ipv6Prefer,
        _ => return Err("openconnect: invalid ip-version".into()),
    };
    // Go time.Duration represents nanoseconds in a signed 64-bit integer.
    for value in [
        options.handshake_timeout,
        options.reconnect_timeout,
        options.dpd_interval,
    ]
    .into_iter()
    .flatten()
    {
        if value > i64::MAX as u64 / 1_000_000_000 {
            return Err("openconnect: timeout exceeds supported duration".into());
        }
    }
    if options
        .cert_expire_warning
        .is_some_and(|days| days > 106751)
    {
        return Err("openconnect: cert-expire-warning exceeds supported duration".into());
    }
    meow_proxy::openconnect_adapter::OpenConnectAdapter::new_configured(
        &options.name,
        meow_proxy::openconnect_adapter::Options {
            server_name: options
                .server_name
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| options.server.clone()),
            server: options.server,
            port: options.port.filter(|port| *port != 0).unwrap_or(443),
            cookie,
            credentials,
            additional_roots: roots,
            mtu: options.mtu.unwrap_or(0),
            handshake_timeout: std::time::Duration::from_secs(
                options.handshake_timeout.unwrap_or(0),
            ),
            udp: options.udp.unwrap_or(true),
            ipv6: !options.ipv6_disabled.unwrap_or(false),
            remote_dns_resolve: options.remote_dns_resolve.unwrap_or(false),
            dns,
            dtls_mode,
        },
        AdvancedOptions {
            reconnect_timeout: std::time::Duration::from_secs(
                options
                    .reconnect_timeout
                    .filter(|timeout| *timeout != 0)
                    .unwrap_or(300),
            ),
            dialer: std::sync::Arc::clone(dialer),
            network: meow_proxy::openconnect_adapter::NetworkOptions {
                interface_name: options.interface_name.unwrap_or_default(),
                routing_mark: options.routing_mark.unwrap_or_default(),
                ip_version,
                tfo: options.tfo.unwrap_or(false),
                mptcp: options.mptcp.unwrap_or(false),
            },
            auth: meow_proxy::openconnect_adapter::AuthOptions {
                token,
                mca: None,
                form_entries: options.form_entries.unwrap_or_default(),
                http_keep_alive_disabled: options.http_keepalive_disabled.unwrap_or(false),
                xml_post_disabled: options.xml_post_disabled.unwrap_or(false),
                external_auth_disabled: options.external_auth_disabled.unwrap_or(false),
                password_authentication_disabled: options
                    .password_authentication_disabled
                    .unwrap_or(false),
            },
            tls: TlsOptions {
                certificate: material(options.cert, "certificate")?,
                key: material(options.key, "private key")?,
                key_password: options.key_password.unwrap_or_default(),
                mca_certificate: material(options.mca_certificate, "MCA certificate")?,
                mca_key: material(options.mca_key, "MCA key")?,
                mca_key_password: options.mca_key_password.unwrap_or_default(),
                cert_expire_warning: options.cert_expire_warning,
                peer_fingerprints,
                system_trust_disabled: options.system_trust_disabled.unwrap_or(false),
                skip_cert_verify: options.skip_cert_verify.unwrap_or(false),
                pfs: options.pfs.unwrap_or(false),
                allow_insecure_crypto: options.allow_insecure_crypto.unwrap_or(false),
            },
            connection: ConnectSettings {
                compression,
                profile,
                base_mtu,
                dpd_interval: std::time::Duration::from_secs(
                    options
                        .dpd_interval
                        .map_or(0, |value| if value == 0 { 0 } else { value.max(2) }),
                ),
            },
            queue_length: options
                .queue_length
                .filter(|length| *length != 0)
                .unwrap_or(32),
            dtls_resumption_only,
            legacy_dtls: options.legacy_dtls.unwrap_or(true),
            dtls_local_port: options.dtls_local_port.unwrap_or(0),
        },
    )
    .map_err(|e| format!("openconnect: {e}"))
}
