# GeoData configuration

meow accepts mihomo's top-level GeoData fields:

```yaml
geodata-mode: true
geodata-loader: standard
geo-auto-update: true
geo-update-interval: 24
geox-url:
  geoip: https://example.test/geoip.dat
  mmdb: https://example.test/country.mmdb
  asn: https://example.test/asn.mmdb
  geosite: https://example.test/geosite.dat
```

| Field | Default | Behavior |
|---|---|---|
| `geodata-mode` | `false` | Selects GeoIP protobuf when true, country MMDB otherwise. |
| `geodata-loader` | `memconservative` | `standard` loads every protobuf category; `memconservative` retains only referenced categories. |
| `geo-auto-update` | `false` | Enables periodic database downloads. |
| `geo-update-interval` | `24` | Hours between refreshes; zero is invalid. |
| `geox-url` | Built-in release URLs | Overrides each database's download URL independently. |

The selected GeoIP format serves both GEOIP/SRC-GEOIP rules and DNS GeoIP fallback
filtering. Protobuf CIDRs support IPv4, IPv6, and inverse entries. They compile
into the same shared country range index as MMDB, so packet matching does not
decode protobuf or query a database reader.

GeoSite supports protobuf `.dat` and the existing MRS formats. Full, suffix,
keyword, regular-expression, and attribute categories retain their existing
matching behavior. Loader selection changes retained data, not rule semantics.

The nested project-specific `geodata:` block remains available for local paths:

```yaml
geodata:
  geoip-path: /data/geoip.dat
  mmdb-path: /data/Country.mmdb
  asn-path: /data/GeoLite2-ASN.mmdb
  geosite-path: /data/geosite.dat
```

Without overrides, files live in meow's data directory (`-d` takes precedence).
The nested `auto-update`, `auto-update-interval`, `url`, `geodata-mode`, and
`geodata-loader` aliases remain accepted. Corresponding top-level values take
precedence. `geoip-matcher` does not change meow's range-index implementation.

Parser tests cover both loaders, country membership, inverse ranges, malformed
and truncated protobuf, URL/path selection, and interval validation.
