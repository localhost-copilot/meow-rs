# OpenClash domain rule-set memory A/B (2026-09-10)

This run compares the ARM64 OpenWrt binary with the same OpenClash
configuration and `geodata_loader=memconservative` on `192.168.6.1`.

The candidate keeps GeoSite's compact trie and changes immutable Domain
rule-provider payloads from the general `DomainTrie<()>` to the same flat,
read-only `CompactDomainTrie`. The matching algorithm remains a suffix walk
with binary search over each node's sorted edges; `+.domain` continues to
match the apex and subdomains.

| build | core SHA-256 | VmRSS | RssAnon | RssFile | threads |
|---|---|---:|---:|---:|---:|
| previous GeoSite compact | `d1c24aff475d2035b022ddceb1c677a07653872aeaa19b90135bbdd28946d55f` | 34,488 KiB | 24,260 KiB | 10,228 KiB | 7 |
| Domain rule-set compact | `e1873cb293268f9c76b874d06af07295f6c1a495941c223690cf993959227e85` | 30,936 KiB | 20,592 KiB | 10,344 KiB | 8 |

The resident set decreased by 3,552 KiB (10.3%); anonymous resident memory
decreased by 3,668 KiB. The candidate's recorded HWM was 61,788 KiB during
restart, compared with 46,180 KiB for the previous build, so HWM is not used
as the improvement metric in this run because startup timing differed.

Validation after restoring the candidate:

- `meow -t` accepted the active OpenClash configuration.
- `/version` returned `v0.23.1`, `meta=true`.
- API counts remained 55 proxies, 134 routing rules, and 98 rule providers.
- Both configured AnyConnect peers passed HTTPS delay checks (48ms and 264ms).
- `cargo test --locked -p meow-trie --lib` passed all 22 tests.
- `cargo test --locked -p meow-rules --all-targets` passed all enabled tests,
  including the GeoSite RSS stress tests.

No node configuration, credentials, or provider payloads are included here.
