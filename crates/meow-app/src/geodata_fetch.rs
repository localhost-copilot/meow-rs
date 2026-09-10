//! Geodata DB download orchestration — startup-fetch (run unconditionally
//! when a target file is missing) and auto-update loop (periodic refresh
//! when `geodata.auto-update: true`).
//!
//! Both entry points are `pub` so downstream FFI callers that build a
//! `Tunnel` directly — bypassing `main.rs` — can wire the same behavior in
//! without reimplementing it.

use meow_common::adapter::Proxy;
use meow_config::geodata::download_and_replace;
use meow_config::raw::RawConfig;
use meow_config::GeoDataConfig;
use meow_dns::resolver::Resolver;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// One geodata DB to consider on startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoTarget {
    pub label: &'static str,
    pub path: PathBuf,
    pub url: String,
}

/// Resolve the three geodata target paths (mmdb / asn / geosite) from `geo`,
/// applying the project-wide defaults when an explicit path was not set.
pub fn compute_targets(geo: &GeoDataConfig) -> [GeoTarget; 3] {
    let (country_path, country_url) = geo.country_database();
    let asn = geo
        .asn_path
        .clone()
        .unwrap_or_else(meow_config::default_asn_path);
    let geosite = geo
        .geosite_path
        .clone()
        .unwrap_or_else(meow_config::default_geosite_path);
    [
        GeoTarget {
            label: if geo.mode { "GeoIP DAT" } else { "GeoIP MMDB" },
            path: country_path,
            url: country_url.into(),
        },
        GeoTarget {
            label: "ASN MMDB",
            path: asn,
            url: geo.asn_url.clone(),
        },
        GeoTarget {
            label: "geosite",
            path: geosite,
            url: geo.geosite_url.clone(),
        },
    ]
}

/// Download each target whose `path` does not yet exist. Returns the list of
/// labels that were successfully fetched (empty if nothing was missing or
/// every fetch failed). Each target is attempted independently — one failure
/// does not skip the others.
pub async fn fetch_missing(
    targets: &[GeoTarget],
    download_proxy: Option<&Arc<dyn Proxy>>,
) -> Vec<&'static str> {
    let mut downloaded = Vec::new();
    for t in targets {
        if t.path.exists() {
            continue;
        }
        info!(
            "geodata startup-fetch: {} missing at {}, downloading",
            t.label,
            t.path.display()
        );
        match download_and_replace(&t.url, &t.path, download_proxy).await {
            Ok(()) => downloaded.push(t.label),
            Err(e) => warn!(
                "geodata startup-fetch: {} download failed: {:#}",
                t.label, e
            ),
        }
    }
    downloaded
}

type RuleProviders =
    Arc<RwLock<std::collections::HashMap<String, Arc<meow_config::rule_provider::RuleProvider>>>>;

/// Fetch absent databases, then refresh rule and DNS classification in memory.
pub async fn run_on_startup(
    geo: GeoDataConfig,
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
    resolver: Arc<Resolver>,
    cache_dir: PathBuf,
    providers: RuleProviders,
) {
    let targets = compute_targets(&geo);
    let route = tunnel.route_snapshot();
    let download_proxy = meow_config::internal_http::first_named_proxy(
        raw_config.read().proxies.as_deref(),
        &route.proxies,
    );
    if fetch_missing(&targets, download_proxy.as_ref())
        .await
        .is_empty()
    {
        return;
    }
    if let Err(error) =
        reload_databases(&tunnel, &raw_config, &resolver, &cache_dir, &providers).await
    {
        warn!("geodata startup-fetch: classification rebuild failed: {error:#}");
    }
}

/// Refresh all selected databases, including the country database, at the
/// configured interval. Existing connections and fake-IP assignments survive.
pub async fn auto_update_loop(
    geo: GeoDataConfig,
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
    resolver: Arc<Resolver>,
    cache_dir: PathBuf,
    providers: RuleProviders,
) {
    let interval = std::time::Duration::from_secs(u64::from(geo.auto_update_interval) * 3600);
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let current = match meow_config::geodata::parse_geodata_config(&raw_config.read()) {
            Ok(current) => current,
            Err(error) => {
                warn!("geodata auto-update: invalid configuration: {error}");
                continue;
            }
        };
        if !current.auto_update {
            continue;
        }
        let route = tunnel.route_snapshot();
        let download_proxy = meow_config::internal_http::first_named_proxy(
            raw_config.read().proxies.as_deref(),
            &route.proxies,
        );
        let mut updated = false;
        for target in compute_targets(&current) {
            match download_and_replace(&target.url, &target.path, download_proxy.as_ref()).await {
                Ok(()) => updated = true,
                Err(error) => warn!("geodata auto-update: {} failed: {error:#}", target.label),
            }
        }
        if updated {
            if let Err(error) =
                reload_databases(&tunnel, &raw_config, &resolver, &cache_dir, &providers).await
            {
                warn!("geodata auto-update: classification rebuild failed: {error:#}");
            }
        }
    }
}

async fn reload_databases(
    tunnel: &Tunnel,
    raw_config: &RwLock<RawConfig>,
    resolver: &Arc<Resolver>,
    cache_dir: &std::path::Path,
    providers: &RuleProviders,
) -> anyhow::Result<()> {
    let raw = raw_config.read().clone();
    let original = serde_yaml::to_value(&raw)?;
    let (_, rules) = tokio::task::spawn_blocking({
        let raw = raw.clone();
        let resolver = Arc::clone(resolver);
        let cache_dir = cache_dir.to_path_buf();
        move || meow_config::rebuild_from_raw_with_resolver(&raw, Some(resolver), Some(&cache_dir))
    })
    .await??;
    let route = tunnel.route_snapshot();
    let providers = providers.read().clone();
    let (policy, fallback) =
        meow_config::dns_parser::prepare_geodata_refresh(&raw, &route.proxies, &providers).await?;
    let current = raw_config.read();
    if serde_yaml::to_value(&*current)? != original {
        info!("geodata: configuration changed during rebuild; keeping current routing");
        return Ok(());
    }
    resolver.replace_geodata(
        policy,
        fallback,
        raw.dns
            .as_ref()
            .and_then(|dns| dns.respect_rules)
            .unwrap_or(false),
    );
    tunnel.update_rules(rules);
    info!("geodata: rules and DNS classification refreshed");
    Ok(())
}

#[cfg(test)]
mod tests {
    fn geosite_fixture(domain: &str) -> Vec<u8> {
        let mut entry = vec![
            0x0a,
            2,
            b'C',
            b'N',
            0x12,
            domain.len() as u8 + 4,
            8,
            3,
            0x12,
            domain.len() as u8,
        ];
        entry.extend_from_slice(domain.as_bytes());
        let mut data = vec![0x0a, entry.len() as u8];
        data.extend_from_slice(&entry);
        data
    }

    async fn dns_fixture(last_octet: u8) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let mut response = buffer[..size].to_vec();
                let mut end = 12;
                while response[end] != 0 {
                    end += usize::from(response[end]) + 1;
                }
                response.truncate(end + 5);
                response[2..4].copy_from_slice(&[0x81, 0x80]);
                response[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
                response.extend_from_slice(&[
                    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, last_octet,
                ]);
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        (addr, task)
    }

    #[tokio::test]
    async fn database_refresh_updates_rules_dns_and_direct_policy_without_resetting_fakeip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geosite.dat");
        std::fs::write(&path, geosite_fixture("a.test")).unwrap();
        let (main, main_task) = dns_fixture(1).await;
        let (policy, policy_task) = dns_fixture(2).await;
        let config = meow_config::load_config_from_str(&format!(
            "geodata:
  geosite-path: '{}'
rules: ['GEOSITE,cn,REJECT', 'MATCH,DIRECT']
dns:
  enable: true
  use-system-hosts: false
  enhanced-mode: fake-ip
  fake-ip-filter: [a.test, b.test]
  nameserver: ['{main}']
  direct-nameserver: ['{main}']
  direct-nameserver-follow-policy: true
  nameserver-policy:
    geosite:cn: ['{policy}#DIRECT']
",
            path.display()
        ))
        .await
        .unwrap();
        let resolver = config.dns.resolver;
        let tunnel = Tunnel::new(Arc::clone(&resolver));
        tunnel.update_routing(config.proxies, config.rules);
        let raw = RwLock::new(config.raw);
        let providers = Arc::new(RwLock::new(config.rule_providers));
        let first = Some("192.0.2.1".parse().unwrap());
        let second = Some("192.0.2.2".parse().unwrap());
        assert_eq!(resolver.lookup_ipv4("a.test").await, second);
        assert_eq!(resolver.lookup_ipv4("b.test").await, first);
        let fake = resolver.lookup_ipv4("sticky.test").await.unwrap();
        assert!(resolver.is_fake_ip(fake));
        let selected = |host: &str| {
            tunnel
                .inner()
                .resolve_proxy(&meow_common::Metadata {
                    host: host.into(),
                    ..Default::default()
                })
                .unwrap()
                .0
                .name()
                .to_owned()
        };
        assert_eq!(selected("a.test"), "REJECT");
        std::fs::write(&path, geosite_fixture("b.test")).unwrap();
        reload_databases(&tunnel, &raw, &resolver, dir.path(), &providers)
            .await
            .unwrap();
        assert_eq!(selected("a.test"), "DIRECT");
        assert_eq!(selected("b.test"), "REJECT");
        assert_eq!(resolver.lookup_ipv4("a.test").await, first);
        assert_eq!(resolver.lookup_ipv4("b.test").await, second);
        assert_eq!(
            resolver
                .direct_resolver()
                .unwrap()
                .lookup_ipv4("b.test")
                .await,
            second
        );
        assert_eq!(resolver.lookup_ipv4("sticky.test").await, Some(fake));
        main_task.abort();
        policy_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_refresh_downloads_the_country_database_too() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = http.local_addr().unwrap();
        let (seen, mut received) = tokio::sync::mpsc::channel(3);
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = http.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let size = stream.read(&mut request).await.unwrap();
                let request = std::str::from_utf8(&request[..size]).unwrap();
                let path = request.split_whitespace().nth(1).unwrap().to_owned();
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnew",
                    )
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
                seen.send(path).await.unwrap();
            }
        });
        let config = meow_config::load_config_from_str(&format!(
            "geo-auto-update: true
geo-update-interval: 1
geox-url:
  mmdb: http://{addr}/country
  asn: http://{addr}/asn
  geosite: http://{addr}/geosite
geodata:
  mmdb-path: '{}'
  asn-path: '{}'
  geosite-path: '{}'
rules: ['MATCH,DIRECT']
",
            dir.path().join("country.mmdb").display(),
            dir.path().join("asn.mmdb").display(),
            dir.path().join("geosite.dat").display()
        ))
        .await
        .unwrap();
        let resolver = config.dns.resolver;
        let tunnel = Tunnel::new(Arc::clone(&resolver));
        tunnel.update_routing(config.proxies, config.rules);
        let task = tokio::spawn(auto_update_loop(
            config.geodata,
            tunnel,
            Arc::new(RwLock::new(config.raw)),
            resolver,
            dir.path().to_path_buf(),
            Arc::new(RwLock::new(config.rule_providers)),
        ));
        tokio::task::yield_now().await;
        assert!(received.try_recv().is_err());
        tokio::time::advance(std::time::Duration::from_secs(3600)).await;
        tokio::time::resume();
        let mut paths = Vec::new();
        for _ in 0..3 {
            paths.push(received.recv().await.unwrap());
        }
        assert_eq!(paths, ["/country", "/asn", "/geosite"]);
        // The server notification precedes the final atomic file rename.
        while !dir.path().join("geosite.dat").exists() {
            tokio::task::yield_now().await;
        }
        for file in ["country.mmdb", "asn.mmdb", "geosite.dat"] {
            assert_eq!(std::fs::read(dir.path().join(file)).unwrap(), b"new");
        }
        task.abort();
        server.await.unwrap();
    }

    use super::*;

    fn cfg_with_paths(
        mmdb: Option<&str>,
        asn: Option<&str>,
        geosite: Option<&str>,
    ) -> GeoDataConfig {
        GeoDataConfig {
            mmdb_path: mmdb.map(PathBuf::from),
            asn_path: asn.map(PathBuf::from),
            geosite_path: geosite.map(PathBuf::from),
            mmdb_url: "https://example.test/country.mmdb".into(),
            asn_url: "https://example.test/asn.mmdb".into(),
            geosite_url: "https://example.test/geosite.mrs".into(),
            ..GeoDataConfig::default()
        }
    }

    #[test]
    fn compute_targets_uses_explicit_paths_when_set() {
        let cfg = cfg_with_paths(
            Some("/tmp/explicit/country.mmdb"),
            Some("/tmp/explicit/asn.mmdb"),
            Some("/tmp/explicit/geosite.mrs"),
        );
        let t = compute_targets(&cfg);
        assert_eq!(t[0].label, "GeoIP MMDB");
        assert_eq!(t[0].path, PathBuf::from("/tmp/explicit/country.mmdb"));
        assert_eq!(t[1].label, "ASN MMDB");
        assert_eq!(t[1].path, PathBuf::from("/tmp/explicit/asn.mmdb"));
        assert_eq!(t[2].label, "geosite");
        assert_eq!(t[2].path, PathBuf::from("/tmp/explicit/geosite.mrs"));
    }

    #[test]
    fn compute_targets_falls_back_to_defaults_when_unset() {
        let cfg = cfg_with_paths(None, None, None);
        let t = compute_targets(&cfg);
        // Defaults are project-defined; we just assert non-empty + matching
        // file basenames so the test isn't tied to the user's home dir.
        assert_eq!(t[0].path, meow_config::default_geoip_path());
        assert_eq!(t[1].path, meow_config::default_asn_path());
        assert_eq!(t[2].path, meow_config::default_geosite_path());
    }

    #[test]
    fn compute_targets_carries_urls() {
        let cfg = cfg_with_paths(None, None, None);
        let t = compute_targets(&cfg);
        assert_eq!(t[0].url, "https://example.test/country.mmdb");
        assert_eq!(t[1].url, "https://example.test/asn.mmdb");
        assert_eq!(t[2].url, "https://example.test/geosite.mrs");
    }

    #[tokio::test]
    async fn fetch_missing_skips_existing_files() {
        // All three targets point at files that already exist → returns empty
        // and never touches the network (the URLs are unreachable).
        let dir = tempfile::tempdir().unwrap();
        let mmdb = dir.path().join("country.mmdb");
        let asn = dir.path().join("asn.mmdb");
        let geosite = dir.path().join("geosite.mrs");
        std::fs::write(&mmdb, b"existing-mmdb").unwrap();
        std::fs::write(&asn, b"existing-asn").unwrap();
        std::fs::write(&geosite, b"existing-geosite").unwrap();

        let cfg = cfg_with_paths(
            Some(mmdb.to_str().unwrap()),
            Some(asn.to_str().unwrap()),
            Some(geosite.to_str().unwrap()),
        );
        let targets = compute_targets(&cfg);
        let downloaded = fetch_missing(&targets, None).await;
        assert!(
            downloaded.is_empty(),
            "no file is missing → no download attempt"
        );
        // Files are unchanged.
        assert_eq!(std::fs::read(&mmdb).unwrap(), b"existing-mmdb");
    }
}
