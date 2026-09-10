use crate::internal_http;
use crate::raw::RawGeoDataConfig;
use anyhow::anyhow;
use meow_common::adapter::Proxy;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

const DEFAULT_MMDB_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/country.mmdb";
const DEFAULT_ASN_URL: &str =
    "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb";
const DEFAULT_GEOSITE_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat";
const DEFAULT_GEOIP_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip.dat";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GeoDataLoader {
    Standard,
    #[default]
    MemConservative,
}

/// Validated `geodata:` config, produced by [`parse_geodata`].
#[derive(Debug, Clone)]
pub struct GeoDataConfig {
    pub mode: bool,
    pub loader: GeoDataLoader,
    pub geoip_path: Option<PathBuf>,
    pub geoip_url: String,
    pub mmdb_path: Option<PathBuf>,
    pub asn_path: Option<PathBuf>,
    pub geosite_path: Option<PathBuf>,
    pub auto_update: bool,
    /// Hours between update checks (≥1).
    pub auto_update_interval: u32,
    pub mmdb_url: String,
    pub asn_url: String,
    pub geosite_url: String,
}

impl Default for GeoDataConfig {
    fn default() -> Self {
        Self {
            mode: false,
            loader: GeoDataLoader::default(),
            geoip_path: None,
            geoip_url: DEFAULT_GEOIP_URL.into(),
            mmdb_path: None,
            asn_path: None,
            geosite_path: None,
            auto_update: false,
            auto_update_interval: 24,
            mmdb_url: DEFAULT_MMDB_URL.to_string(),
            asn_url: DEFAULT_ASN_URL.to_string(),
            geosite_url: DEFAULT_GEOSITE_URL.to_string(),
        }
    }
}

impl GeoDataConfig {
    pub fn country_database(&self) -> (PathBuf, &str) {
        if self.mode {
            (
                self.geoip_path
                    .clone()
                    .unwrap_or_else(crate::default_geoip_dat_path),
                &self.geoip_url,
            )
        } else {
            (
                self.mmdb_path
                    .clone()
                    .unwrap_or_else(crate::default_geoip_path),
                &self.mmdb_url,
            )
        }
    }
}

/// Apply mihomo's top-level fields, retaining the project's nested path aliases.
/// Explicit top-level values take precedence over corresponding nested values.
pub fn parse_geodata_config(raw: &crate::raw::RawConfig) -> Result<GeoDataConfig, anyhow::Error> {
    let mut nested = raw.geodata.clone().unwrap_or_default();
    if let Some(mode) = raw.geodata_mode {
        nested.geodata_mode = Some(mode.into());
    }
    if let Some(loader) = &raw.geodata_loader {
        nested.geodata_loader = Some(loader.clone().into());
    }
    if let Some(update) = raw.geo_auto_update {
        nested.auto_update = update;
    }
    if let Some(interval) = raw.geo_update_interval {
        nested.auto_update_interval = Some(interval);
    }
    if let Some(urls) = &raw.geox_url {
        let target = nested.url.get_or_insert_with(Default::default);
        for (dest, source) in [
            (&mut target.geoip, &urls.geoip),
            (&mut target.mmdb, &urls.mmdb),
            (&mut target.asn, &urls.asn),
            (&mut target.geosite, &urls.geosite),
        ] {
            if source.is_some() {
                dest.clone_from(source);
            }
        }
    }
    parse_geodata(Some(&nested))
}

/// Parse and validate the raw `geodata:` block. Returns `GeoDataConfig::default()`
/// when the block is absent.
pub fn parse_geodata(raw: Option<&RawGeoDataConfig>) -> Result<GeoDataConfig, anyhow::Error> {
    let Some(r) = raw else {
        return Ok(GeoDataConfig::default());
    };

    let mode = match &r.geodata_mode {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| anyhow!("geodata-mode must be a boolean"))?,
        None => false,
    };
    let loader = match r
        .geodata_loader
        .as_ref()
        .and_then(serde_yaml::Value::as_str)
    {
        None if r.geodata_loader.is_none() => GeoDataLoader::MemConservative,
        Some("memconservative") => GeoDataLoader::MemConservative,
        Some("standard") => GeoDataLoader::Standard,
        _ => {
            return Err(anyhow!(
                "geodata-loader must be standard or memconservative"
            ))
        }
    };
    if r.geoip_matcher.is_some() {
        warn!("geodata.geoip-matcher: meow uses its IP range index for both database formats");
    }

    let interval = r.auto_update_interval.unwrap_or(24);
    if interval == 0 {
        return Err(anyhow!(
            "geodata.auto-update-interval must be at least 1 hour (got 0)"
        ));
    }

    let urls = r.url.as_ref();
    Ok(GeoDataConfig {
        mode,
        loader,
        geoip_path: r.geoip_path.as_deref().map(PathBuf::from),
        geoip_url: urls
            .and_then(|u| u.geoip.clone())
            .unwrap_or_else(|| DEFAULT_GEOIP_URL.into()),
        mmdb_path: r.mmdb_path.as_deref().map(PathBuf::from),
        asn_path: r.asn_path.as_deref().map(PathBuf::from),
        geosite_path: r.geosite_path.as_deref().map(PathBuf::from),
        auto_update: r.auto_update,
        auto_update_interval: interval,
        mmdb_url: urls
            .and_then(|u| u.mmdb.clone())
            .unwrap_or_else(|| DEFAULT_MMDB_URL.to_string()),
        asn_url: urls
            .and_then(|u| u.asn.clone())
            .unwrap_or_else(|| DEFAULT_ASN_URL.to_string()),
        geosite_url: urls
            .and_then(|u| u.geosite.clone())
            .unwrap_or_else(|| DEFAULT_GEOSITE_URL.to_string()),
    })
}

/// Download `url` and atomically replace `dest` via a `.tmp` sibling.
///
/// When `proxy` is `Some`, the HTTP fetch is tunneled through that proxy
/// adapter (used so GFW-blocked CDNs stay reachable on background refresh);
/// otherwise the OS handles connectivity directly.
///
/// Returns `Ok(())` on success. On failure the temp file is removed (best-
/// effort) and the original `dest` is untouched.
pub async fn download_and_replace(
    url: &str,
    dest: &Path,
    proxy: Option<&Arc<dyn Proxy>>,
) -> Result<(), anyhow::Error> {
    let tmp = dest.with_extension("tmp");

    if let Some(p) = proxy {
        info!(
            "auto-update: downloading {} from {} via proxy '{}'",
            dest.display(),
            url,
            p.name()
        );
    } else {
        info!("auto-update: downloading {} from {}", dest.display(), url);
    }

    let bytes = internal_http::fetch(url, proxy, &[])
        .await
        .map_err(|e| anyhow!("fetching {url}: {e}"))?;

    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&tmp, &bytes).await?;

    if let Err(e) = tokio::fs::rename(&tmp, dest).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(anyhow!(
            "atomic rename {} → {}: {}",
            tmp.display(),
            dest.display(),
            e
        ));
    }

    info!(
        "auto-update: {} updated ({} bytes)",
        dest.display(),
        bytes.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn top_level_geo_settings_load_country_dat_and_select_loader() {
        let dir = tempfile::tempdir().unwrap();
        let country = dir.path().join("geoip.dat");
        std::fs::write(
            &country,
            [
                0x0a, 14, 0x0a, 2, b'C', b'N', 0x12, 8, 0x0a, 4, 192, 0, 2, 0, 0x10, 24,
            ],
        )
        .unwrap();
        let geosite = dir.path().join("geosite.dat");
        let mut sites = Vec::new();
        for (code, domain) in [(b"CN", "cn.test"), (b"US", "us.test")] {
            let mut entry = vec![0x0a, 2];
            entry.extend_from_slice(code);
            entry.extend_from_slice(&[
                0x12,
                domain.len() as u8 + 4,
                8,
                3,
                0x12,
                domain.len() as u8,
            ]);
            entry.extend_from_slice(domain.as_bytes());
            sites.extend_from_slice(&[0x0a, entry.len() as u8]);
            sites.extend_from_slice(&entry);
        }
        std::fs::write(&geosite, sites).unwrap();
        let yaml = format!(
            "geodata-mode: true
geodata-loader: standard
geo-auto-update: true
geo-update-interval: 7
geox-url: {{geoip: 'https://example.test/custom.dat'}}
geodata:
  geoip-path: '{}'
  geosite-path: '{}'
rules: ['GEOIP,CN,REJECT', 'GEOSITE,cn,REJECT', 'MATCH,DIRECT']
",
            country.display(),
            geosite.display()
        );
        let mut raw: crate::raw::RawConfig = serde_yaml::from_str(&yaml).unwrap();
        let parsed = super::parse_geodata_config(&raw).unwrap();
        assert!(parsed.mode && parsed.auto_update);
        assert_eq!(parsed.auto_update_interval, 7);
        assert_eq!(
            parsed.country_database(),
            (country, "https://example.test/custom.dat")
        );
        let context = crate::build_parser_context_from_raw(&raw, &Default::default()).unwrap();
        let geoip = context.geoip.unwrap();
        assert!(geoip
            .ranges_for("cn")
            .v4
            .contains(&"192.0.2.17".parse::<std::net::Ipv4Addr>().unwrap()));
        assert_eq!(context.geosite.unwrap().category_count(), 2);
        raw.geodata_loader = Some("memconservative".into());
        let context = crate::build_parser_context_from_raw(&raw, &Default::default()).unwrap();
        assert_eq!(context.geosite.unwrap().category_count(), 1);
        raw.geo_update_interval = Some(0);
        assert!(super::parse_geodata_config(&raw).is_err());
    }

    use super::*;
    use crate::raw::{RawGeoDataConfig, RawGeoDataUrls};

    fn raw_defaults() -> RawGeoDataConfig {
        RawGeoDataConfig::default()
    }

    #[test]
    fn absent_block_returns_defaults() {
        let cfg = parse_geodata(None).unwrap();
        assert!(!cfg.auto_update);
        assert_eq!(cfg.auto_update_interval, 24);
        assert!(cfg.mmdb_path.is_none());
        assert!(cfg.asn_path.is_none());
        assert!(cfg.geosite_path.is_none());
        assert!(cfg.mmdb_url.contains("country.mmdb"));
        assert!(cfg.asn_url.contains("GeoLite2-ASN"));
        assert!(cfg.geosite_url.contains("geosite.dat"));
    }

    #[test]
    fn explicit_paths_override_discovery() {
        let raw = RawGeoDataConfig {
            mmdb_path: Some("/custom/Country.mmdb".to_string()),
            asn_path: Some("/custom/ASN.mmdb".to_string()),
            geosite_path: Some("/custom/geosite.mrs".to_string()),
            ..raw_defaults()
        };
        let cfg = parse_geodata(Some(&raw)).unwrap();
        assert_eq!(
            cfg.mmdb_path.unwrap().to_str().unwrap(),
            "/custom/Country.mmdb"
        );
        assert_eq!(cfg.asn_path.unwrap().to_str().unwrap(), "/custom/ASN.mmdb");
        assert_eq!(
            cfg.geosite_path.unwrap().to_str().unwrap(),
            "/custom/geosite.mrs"
        );
    }

    #[test]
    fn url_overrides_replace_defaults() {
        let raw = RawGeoDataConfig {
            url: Some(RawGeoDataUrls {
                geoip: None,
                mmdb: Some("https://example.com/country.mmdb".to_string()),
                asn: None,
                geosite: Some("https://example.com/geosite.mrs".to_string()),
            }),
            ..raw_defaults()
        };
        let cfg = parse_geodata(Some(&raw)).unwrap();
        assert_eq!(cfg.mmdb_url, "https://example.com/country.mmdb");
        assert!(cfg.asn_url.contains("GeoLite2-ASN")); // default preserved
        assert_eq!(cfg.geosite_url, "https://example.com/geosite.mrs");
    }

    #[test]
    fn interval_zero_is_hard_error() {
        let raw = RawGeoDataConfig {
            auto_update_interval: Some(0),
            ..raw_defaults()
        };
        let err = parse_geodata(Some(&raw)).unwrap_err();
        assert!(
            err.to_string().contains("at least 1 hour"),
            "error should mention minimum interval: {err}"
        );
    }

    #[test]
    fn absent_interval_defaults_to_24() {
        let raw = RawGeoDataConfig {
            auto_update: true,
            auto_update_interval: None,
            ..raw_defaults()
        };
        let cfg = parse_geodata(Some(&raw)).unwrap();
        assert_eq!(cfg.auto_update_interval, 24);
    }

    #[test]
    fn upstream_only_fields_do_not_error() {
        // geodata-mode, geodata-loader, geoip-matcher accepted without error.
        let raw = RawGeoDataConfig {
            geodata_mode: Some(serde_yaml::Value::Bool(true)),
            geodata_loader: Some(serde_yaml::Value::String("standard".to_string())),
            geoip_matcher: Some(serde_yaml::Value::String("succinct".to_string())),
            ..raw_defaults()
        };
        // Must not error — warn-only (Class B per ADR-0002).
        parse_geodata(Some(&raw)).unwrap();
    }
}
