//! Bounded AnyConnect XML form authentication over a verified TLS connection.
//! Forms and server messages are never included in errors: they can contain secrets.

use crate::{header_line, invalid, HEADER_LIMIT};
use base64::Engine;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

const BODY_LIMIT: usize = 65536;

#[derive(Clone, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct FormEntry {
    pub form_id: String,
    pub submission_key: String,
    pub name: String,
    pub value: String,
    pub promote: bool,
}

#[derive(Default)]
pub struct AuthOptions {
    pub form_entries: Vec<FormEntry>,
    pub http_keep_alive_disabled: bool,
    pub xml_post_disabled: bool,
    pub external_auth_disabled: bool,
    pub password_authentication_disabled: bool,
    pub token: Option<crate::token::Token>,
    pub mca: Option<std::sync::Arc<dyn MultipleCertificate>>,
}

/// Signs the gateway's exact XML challenge with the secondary client identity.
pub trait MultipleCertificate: Send + Sync {
    fn sign(&self, offered_hashes: &[&str], challenge: &[u8]) -> io::Result<CertificateResponse>;
}

pub struct CertificateResponse {
    pub certificates_pkcs7: Vec<u8>,
    pub hash_algorithm: String,
    pub signature: Vec<u8>,
}

impl AuthOptions {
    pub fn validate(&self) -> io::Result<()> {
        if let Some(token) = &self.token {
            token.validate()?;
        }
        if self.form_entries.len() > 256 {
            return Err(invalid("too many authentication form entries"));
        }
        for entry in &self.form_entries {
            if entry.submission_key.is_empty()
                && (entry.form_id.is_empty() || entry.name.is_empty())
                || entry.promote && !entry.value.is_empty()
                || entry.value.len() > 4096
            {
                return Err(invalid("invalid authentication form entry"));
            }
            for value in [&entry.form_id, &entry.submission_key, &entry.name] {
                crate::settings::validate_header(value)?;
            }
        }
        Ok(())
    }

    fn entry(&self, form: &str, name: &str, index: usize) -> Option<&FormEntry> {
        let key = format!("{form}:{name}:{}", index + 1);
        self.form_entries
            .iter()
            .rev()
            .find(|entry| !entry.submission_key.is_empty() && entry.submission_key == key)
            .or_else(|| {
                self.form_entries.iter().rev().find(|entry| {
                    entry.submission_key.is_empty() && entry.form_id == form && entry.name == name
                })
            })
    }

    fn capabilities(&self) -> String {
        let browser = if self.external_auth_disabled {
            ""
        } else {
            "<auth-method>single-sign-on-v2</auth-method>"
        };
        let mca = if self.mca.is_some() {
            "<auth-method>multiple-cert</auth-method>"
        } else {
            ""
        };
        format!("<capabilities>{browser}{mca}</capabilities>")
    }
}

/// Noninteractive credentials; deliberately does not implement Debug.
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub authgroup: Option<String>,
}

impl Credentials {
    pub fn validate(&self) -> io::Result<()> {
        if [&self.username, &self.password]
            .into_iter()
            .chain(self.authgroup.iter())
            .any(|value| value.len() > 4096 || value.chars().any(char::is_control))
            || self.authgroup.as_ref().is_some_and(String::is_empty)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid OpenConnect credentials",
            ));
        }
        Ok(())
    }
}

/// Authenticate using XML username/password forms and optional group selection.
/// Unsupported challenges, HTTP redirects, and repeated password
/// prompts fail without resubmitting credentials. The caller bounds total duration.
pub async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    authority: &str,
    credentials: &Credentials,
) -> io::Result<(BufReader<S>, String)> {
    authenticate_with_profile(
        stream,
        authority,
        credentials,
        &crate::settings::ClientProfile::default(),
    )
    .await
}

pub async fn authenticate_with_profile<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    authority: &str,
    credentials: &Credentials,
    profile: &crate::settings::ClientProfile,
) -> io::Result<(BufReader<S>, String)> {
    authenticate_configured(
        stream,
        authority,
        credentials,
        profile,
        &AuthOptions::default(),
        || {
            std::future::ready(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "authentication needs a new TLS connection",
            )))
        },
    )
    .await
}

pub async fn authenticate_configured<S, F, Fut>(
    stream: S,
    authority: &str,
    credentials: &Credentials,
    profile: &crate::settings::ClientProfile,
    settings: &AuthOptions,
    mut reconnect: F,
) -> io::Result<(BufReader<S>, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = io::Result<S>>,
{
    credentials.validate()?;
    profile.validate()?;
    settings.validate()?;
    if authority.is_empty() || authority.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(invalid("invalid authentication authority"));
    }
    let mut stream = BufReader::new(stream);
    let mut cookies = BTreeMap::new();
    let mut path = "/".to_owned();
    let group = credentials
        .authgroup
        .as_ref()
        .map_or_else(String::new, |group| {
            format!("<group-select>{}</group-select>", escape(group))
        });
    let mut body = format!("<?xml version=\"1.0\"?><config-auth client=\"vpn\" type=\"init\">{}{}<group-access>https://{}/</group-access>{group}</config-auth>", profile.xml(), settings.capabilities(), escape(authority));
    if settings.xml_post_disabled {
        body.clear();
    }
    let mut method = if settings.xml_post_disabled {
        "GET"
    } else {
        "POST"
    };
    let content_type = if settings.xml_post_disabled {
        "application/x-www-form-urlencoded"
    } else {
        "text/xml"
    };
    let mut password_sent = false;
    let mut tokens = crate::token::Generator::new(settings.token.as_ref());
    let mut bearer_sent = false;
    for _ in 0..6 {
        let cookie = cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        if cookie.len() > HEADER_LIMIT / 2 {
            return Err(invalid("authentication cookie jar too large"));
        }
        let connection = if settings.http_keep_alive_disabled {
            "Connection: close\r\n"
        } else {
            ""
        };
        let transcend = if settings.xml_post_disabled {
            ""
        } else {
            "X-Transcend-Version: 1\r\n"
        };
        let authorization = if bearer_sent {
            format!(
                "Authorization: Bearer {}\r\n",
                settings.token.as_ref().expect("OIDC token").secret
            )
        } else {
            String::new()
        };
        let request = format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {}\r\n{transcend}{connection}{authorization}Content-Type: {content_type}\r\nAccept: text/xml\r\nAccept-Encoding: identity\r\nCookie: {cookie}\r\nContent-Length: {}\r\n\r\n{body}", profile.user_agent, body.len());
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let (response, close, unauthorized) = response(&mut stream, &mut cookies).await?;
        if unauthorized {
            if bearer_sent
                || !settings
                    .token
                    .as_ref()
                    .is_some_and(|token| token.mode == "oidc")
            {
                return Err(denied("OpenConnect credentials rejected"));
            }
            bearer_sent = true;
            if close || settings.http_keep_alive_disabled {
                drop(stream);
                stream = BufReader::new(reconnect().await?);
            }
            continue;
        }
        let reply = if settings.xml_post_disabled && cookies.contains_key("webvpn") {
            Reply::Complete(None)
        } else {
            form_reply(
                &response,
                credentials,
                &mut password_sent,
                profile,
                settings,
                &mut tokens,
            )?
        };
        if close || settings.http_keep_alive_disabled {
            drop(stream);
            stream = BufReader::new(reconnect().await?);
        }
        match reply {
            Reply::Complete(token) => {
                let cookie = cookies
                    .remove("webvpn")
                    .or(token)
                    .ok_or_else(|| invalid("authentication completed without session cookie"))?;
                validate_cookie_value(&cookie)?;
                if cookie.is_empty() {
                    return Err(invalid("empty authentication cookie"));
                }
                return Ok((stream, cookie));
            }
            Reply::Form { action, xml } => {
                if !action.is_empty() {
                    path = action;
                }
                body = xml;
                method = "POST";
            }
        }
    }
    Err(denied("OpenConnect authentication exceeded form limit"))
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn validate_cookie_value(value: &str) -> io::Result<()> {
    if value.len() > 8192 || value.bytes().any(|b| b <= b' ' || b >= 0x7f || b == b';') {
        return Err(invalid("invalid authentication cookie"));
    }
    Ok(())
}

async fn response<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
    cookies: &mut BTreeMap<String, String>,
) -> io::Result<(String, bool, bool)> {
    let mut remaining = HEADER_LIMIT;
    let status = header_line(stream, &mut remaining).await?;
    let mut status = status.split_whitespace();
    if !matches!(status.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(invalid("invalid authentication HTTP response"));
    }
    let unauthorized = match status.next() {
        Some("200") => false,
        Some("401") => true,
        Some("403") => return Err(denied("OpenConnect credentials rejected")),
        Some("500" | "502" | "503" | "504") => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "authentication gateway temporarily unavailable",
            ))
        }
        _ => {
            return Err(invalid(
                "unsupported authentication HTTP status or redirect",
            ))
        }
    };
    let mut length = None;
    let mut chunked = false;
    let mut close = false;
    let mut bearer = false;
    loop {
        let line = header_line(stream, &mut remaining).await?;
        if line == "\r\n" {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("invalid authentication HTTP header"))?;
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "connection" => {
                close |= value
                    .split(',')
                    .any(|value| value.trim().eq_ignore_ascii_case("close"));
            }
            "www-authenticate" => bearer |= bearer_challenge(value),
            "content-length" => {
                let size: usize = value
                    .parse()
                    .map_err(|_| invalid("invalid authentication body length"))?;
                if length.replace(size).is_some() || size > BODY_LIMIT {
                    return Err(invalid("duplicate or oversized authentication body length"));
                }
            }
            "transfer-encoding" => {
                if chunked || !value.eq_ignore_ascii_case("chunked") {
                    return Err(invalid("unsupported authentication transfer encoding"));
                }
                chunked = true;
            }
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => {
                return Err(invalid("unsupported authentication content encoding"))
            }
            "set-cookie" => {
                let (name, value) = value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .split_once('=')
                    .ok_or_else(|| invalid("invalid authentication cookie"))?;
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                {
                    return Err(invalid("invalid authentication cookie name"));
                }
                validate_cookie_value(value)?;
                if cookies.len() >= 32 && !cookies.contains_key(name) {
                    return Err(invalid("too many authentication cookies"));
                }
                cookies.insert(name.to_owned(), value.to_owned());
            }
            _ => {}
        }
    }
    if chunked && length.is_some() {
        return Err(invalid("ambiguous authentication body framing"));
    }
    if unauthorized && !bearer {
        return Err(denied("OpenConnect credentials rejected"));
    }
    let mut body = Vec::new();
    if chunked {
        let mut framing_budget = HEADER_LIMIT;
        loop {
            let line = header_line(stream, &mut framing_budget).await?;
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| invalid("invalid authentication chunk length"))?;
            if size == 0 {
                while header_line(stream, &mut framing_budget).await? != "\r\n" {}
                break;
            }
            if size > BODY_LIMIT - body.len() {
                return Err(invalid("authentication body too large"));
            }
            let start = body.len();
            body.resize(start + size, 0);
            stream.read_exact(&mut body[start..]).await?;
            let mut crlf = [0; 2];
            stream.read_exact(&mut crlf).await?;
            if crlf != *b"\r\n" {
                return Err(invalid("invalid authentication chunk ending"));
            }
        }
    } else {
        let size = length
            .ok_or_else(|| invalid("authentication response requires bounded body framing"))?;
        body.resize(size, 0);
        stream.read_exact(&mut body).await?;
    }
    String::from_utf8(body)
        .map(|body| (body, close, unauthorized))
        .map_err(|_| invalid("invalid authentication XML encoding"))
}

fn bearer_challenge(value: &str) -> bool {
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    for (index, byte) in value.bytes().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte == b',' {
            if value[start..index]
                .split_whitespace()
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case("bearer"))
            {
                return true;
            }
            start = index + 1;
        }
    }
    value[start..]
        .split_whitespace()
        .next()
        .is_some_and(|word| word.eq_ignore_ascii_case("bearer"))
}

enum Reply {
    Complete(Option<String>),
    Form { action: String, xml: String },
}

pub(crate) fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn form_reply(
    xml: &str,
    credentials: &Credentials,
    password_sent: &mut bool,
    profile: &crate::settings::ClientProfile,
    settings: &AuthOptions,
    tokens: &mut crate::token::Generator<'_>,
) -> io::Result<Reply> {
    // The protocol includes an external DOCTYPE declaration. No entity resolver
    // is installed: parsing cannot access the network or local filesystem.
    if xml.contains("<!ENTITY") {
        return Err(invalid(
            "authentication entity declarations are unsupported",
        ));
    }
    let document = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            nodes_limit: 2048,
            entity_resolver: None,
        },
    )
    .map_err(|_| invalid("invalid authentication XML"))?;
    let root = document.root_element();
    if root.tag_name().name() != "config-auth"
        && !(settings.xml_post_disabled && root.has_tag_name("auth"))
    {
        return Err(invalid("unsupported authentication document"));
    }
    if root
        .descendants()
        .any(|node| node.has_tag_name("host-scan") || node.has_tag_name("csd"))
    {
        return Err(invalid("host-scan authentication is unsupported"));
    }
    if root.descendants().any(|node| node.has_tag_name("error")) {
        return Err(denied("OpenConnect authentication rejected"));
    }
    if let Some(request) = root
        .children()
        .find(|node| node.has_tag_name("multiple-client-cert-request"))
    {
        let identity = settings
            .mca
            .as_ref()
            .ok_or_else(|| denied("gateway requires an MCA identity"))?;
        let hashes: Vec<_> = request
            .children()
            .filter(|node| node.has_tag_name("hash-algorithm"))
            .filter_map(|node| node.text())
            .collect();
        let response = identity.sign(&hashes, xml.as_bytes())?;
        let base64 = base64::engine::general_purpose::STANDARD;
        let opaque = root
            .children()
            .filter(|node| node.has_tag_name("opaque"))
            .map(|node| &xml[node.range()])
            .collect::<String>();
        let body = format!("<?xml version=\"1.0\"?><config-auth client=\"vpn\" type=\"auth-reply\" aggregate-auth-version=\"2\">{}{}<session-token/><session-id/>{opaque}<auth><client-cert-chain cert-store=\"1M\"><client-cert-sent-via-protocol/></client-cert-chain><client-cert-chain cert-store=\"1U\"><client-cert cert-format=\"pkcs7\">{}</client-cert><client-cert-auth-signature hash-algorithm-chosen=\"{}\">{}</client-cert-auth-signature></client-cert-chain></auth></config-auth>", profile.xml(), settings.capabilities(), base64.encode(response.certificates_pkcs7), escape(&response.hash_algorithm), base64.encode(response.signature));
        if body.len() > BODY_LIMIT {
            return Err(invalid("MCA authentication response too large"));
        }
        return Ok(Reply::Form {
            action: String::new(),
            xml: body,
        });
    }
    if root.attribute("type") == Some("complete") {
        let token = root
            .descendants()
            .find(|node| node.has_tag_name("session-token"))
            .and_then(|node| node.text())
            .map(str::to_owned);
        return Ok(Reply::Complete(token));
    }
    if root
        .descendants()
        .any(|node| node.has_tag_name("sso-v2-login") || node.has_tag_name("sso-v2-login-final"))
    {
        return Err(denied(if settings.external_auth_disabled {
            "external authentication is disabled"
        } else {
            "gateway requires interactive browser authentication; provide a cookie"
        }));
    }
    if root.attribute("type") != Some("auth-request")
        && !(settings.xml_post_disabled && root.has_tag_name("auth"))
    {
        return Err(invalid("unsupported authentication response"));
    }
    let form = root
        .descendants()
        .find(|node| node.has_tag_name("form"))
        .ok_or_else(|| invalid("authentication form missing"))?;
    if settings.password_authentication_disabled {
        return Err(denied(
            "gateway requested a form while password authentication is disabled",
        ));
    }
    let form_id = root
        .descendants()
        .find(|node| node.has_tag_name("auth"))
        .and_then(|node| node.attribute("id"))
        .unwrap_or("");
    let action = form.attribute("action").unwrap_or("/");
    if !action.starts_with('/')
        || action.starts_with("//")
        || action
            .bytes()
            .any(|b| b <= b' ' || b >= 0x7f || b == b'\\' || b == b'#')
        || !form
            .attribute("method")
            .unwrap_or("post")
            .eq_ignore_ascii_case("post")
    {
        return Err(invalid("unsupported authentication form action"));
    }
    let mut fields = BTreeMap::new();
    let mut token_generated = false;
    let successor_otp = *password_sent
        && form_id == "main"
        && form
            .descendants()
            .filter(|node| node.has_tag_name("input") || node.has_tag_name("select"))
            .all(|node| {
                node.attribute("type") == Some("hidden")
                    || node.attribute("type") == Some("password")
                        && node.attribute("name") == Some("password")
            })
        && root
            .descendants()
            .filter(|node| node.has_tag_name("message"))
            .filter_map(|node| node.text())
            .any(|message| {
                let message = message.to_ascii_lowercase().replace('-', " ");
                ["otp password", "one time password", "one time passcode"]
                    .iter()
                    .any(|word| message.contains(word))
            });
    // AnyConnect submission keys number select controls before input controls.
    for (index, node) in form
        .descendants()
        .filter(|node| node.has_tag_name("select"))
        .chain(form.descendants().filter(|node| node.has_tag_name("input")))
        .filter(|node| node.attribute("type") != Some("submit"))
        .enumerate()
    {
        let name = node
            .attribute("name")
            .ok_or_else(|| invalid("authentication field name missing"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || !name.as_bytes()[0].is_ascii_alphabetic()
        {
            return Err(invalid("invalid authentication field name"));
        }
        let entry = settings.entry(form_id, name, index);
        if entry.is_some_and(|entry| entry.promote) {
            return Err(denied(
                "promoted form entry requires interactive authentication",
            ));
        }
        let configured = entry.map(|entry| &entry.value);
        let value = if node.has_tag_name("select") {
            if configured.is_none() && name != "group_list" && name != "group-select" {
                return Err(invalid("unsupported authentication selection"));
            }
            let options: Vec<_> = node
                .children()
                .filter(|node| node.has_tag_name("option"))
                .collect();
            let chosen = if let Some(group) = configured.or(credentials.authgroup.as_ref()) {
                options.iter().find(|node| {
                    node.attribute("value") == Some(group.as_str())
                        || node.text() == Some(group.as_str())
                })
            } else if options.len() == 1 {
                options.first()
            } else {
                options
                    .iter()
                    .find(|node| node.attribute("selected").is_some())
            }
            .ok_or_else(|| invalid("authentication requires a valid authgroup"))?;
            chosen
                .attribute("value")
                .or_else(|| chosen.text())
                .unwrap_or("")
                .to_owned()
        } else if let Some(value) = configured {
            value.clone()
        } else if node.attribute("type") == Some("password")
            && tokens.enabled()
            && !token_generated
            && (name == "secondary_password"
                || form_id == "challenge"
                || tokens.is_rsa() && matches!(name, "password" | "answer")
                || successor_otp && name == "password")
        {
            token_generated = true;
            tokens.generate()?
        } else {
            match (name, node.attribute("type").unwrap_or("text")) {
                ("username", "text") if !credentials.username.is_empty() => {
                    credentials.username.clone()
                }
                ("password", "password") if !*password_sent && !credentials.password.is_empty() => {
                    credentials.password.clone()
                }
                ("password", "password") => {
                    return Err(denied("repeated password or MFA challenge is unsupported"))
                }
                (_, "hidden") => node.attribute("value").unwrap_or("").to_owned(),
                (_, "submit") => continue,
                _ => return Err(invalid("unsupported authentication challenge")),
            }
        };
        let name = if name == "group_list" && !settings.xml_post_disabled {
            "group-select"
        } else {
            name
        };
        if fields.insert(name, value).is_some() {
            return Err(invalid("duplicate authentication field"));
        }
    }
    if fields.is_empty() {
        return Err(invalid("empty authentication form"));
    }
    *password_sent |= fields.contains_key("password");
    if settings.xml_post_disabled {
        return Ok(Reply::Form {
            action: action.to_owned(),
            xml: url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(fields)
                .finish(),
        });
    }
    let mut reply = format!(
        "<?xml version=\"1.0\"?><config-auth client=\"vpn\" type=\"auth-reply\">{}{}",
        profile.xml(),
        settings.capabilities()
    );
    for opaque in root.children().filter(|node| node.has_tag_name("opaque")) {
        reply.push_str(&xml[opaque.range()]);
    }
    if let Some(group) = fields.remove("group-select") {
        let _ = write!(reply, "<group-select>{}</group-select>", escape(&group));
    }
    reply.push_str("<auth>");
    for (name, value) in fields {
        let _ = write!(reply, "<{name}>{}</{name}>", escape(&value));
    }
    reply.push_str("</auth></config-auth>");
    if reply.len() > BODY_LIMIT {
        return Err(invalid("authentication reply too large"));
    }
    Ok(Reply::Form {
        action: action.to_owned(),
        xml: reply,
    })
}
