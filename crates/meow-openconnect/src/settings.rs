//! Client identity shared by authentication and the CSTP request.

use std::fmt::Write;
use std::io;

#[derive(Clone, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Mobile {
    pub platform_version: String,
    pub device_type: String,
    pub device_unique_id: String,
}

#[derive(Clone)]
pub struct ClientProfile {
    pub reported_os: String,
    pub user_agent: String,
    pub version: String,
    pub local_hostname: String,
    pub mobile: Option<Mobile>,
}

impl Default for ClientProfile {
    fn default() -> Self {
        Self {
            reported_os: if cfg!(target_os = "windows") {
                "win"
            } else if cfg!(target_os = "macos") {
                "mac-intel"
            } else if cfg!(target_os = "android") {
                "android"
            } else if cfg!(target_os = "ios") {
                "apple-ios"
            } else if cfg!(target_pointer_width = "64") {
                "linux-64"
            } else {
                "linux"
            }
            .into(),
            user_agent: "AnyConnect-compatible OpenConnect VPN Agent v9.21".into(),
            version: "v9.21".into(),
            local_hostname: hostname::get()
                .map(|name| name.to_string_lossy().into_owned())
                .ok()
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "localhost".into()),
            mobile: None,
        }
    }
}

impl ClientProfile {
    pub fn validate(&self) -> io::Result<()> {
        if !matches!(
            self.reported_os.as_str(),
            "linux" | "linux-64" | "win" | "mac-intel" | "android" | "apple-ios"
        ) {
            return Err(crate::invalid("invalid OpenConnect reported-os"));
        }
        for value in [&self.user_agent, &self.version, &self.local_hostname] {
            validate_header(value)?;
        }
        if let Some(mobile) = &self.mobile {
            for value in [
                &mobile.platform_version,
                &mobile.device_type,
                &mobile.device_unique_id,
            ] {
                if value.is_empty() {
                    return Err(crate::invalid("mobile identity requires all three fields"));
                }
                validate_header(value)?;
            }
        }
        Ok(())
    }

    pub(crate) fn xml(&self) -> String {
        let escape = crate::auth::escape;
        let attributes = self.mobile.as_ref().map_or_else(String::new, |mobile| {
            format!(
                " platform-version=\"{}\" device-type=\"{}\" unique-id=\"{}\"",
                escape(&mobile.platform_version),
                escape(&mobile.device_type),
                escape(&mobile.device_unique_id)
            )
        });
        format!(
            "<version who=\"vpn\">{}</version><device-id{attributes}>{}</device-id>",
            escape(&self.version),
            escape(&self.reported_os)
        )
    }

    pub(crate) fn headers(&self) -> String {
        let mut headers = format!("X-CSTP-Hostname: {}\r\n", self.local_hostname);
        if let Some(mobile) = &self.mobile {
            for (name, value) in [
                ("ClientVersion", &self.version),
                ("Platform", &self.reported_os),
                ("PlatformVersion", &mobile.platform_version),
                ("DeviceType", &mobile.device_type),
                ("Device-UniqueID", &mobile.device_unique_id),
            ] {
                let _ = write!(headers, "X-AnyConnect-Identifier-{name}: {value}\r\n");
            }
        }
        headers
    }
}

pub(crate) fn validate_header(value: &str) -> io::Result<()> {
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(crate::invalid("invalid OpenConnect header value"));
    }
    Ok(())
}
