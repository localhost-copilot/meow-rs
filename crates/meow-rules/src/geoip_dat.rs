//! V2Ray GeoIPList: country_code (1), repeated CIDR (2), inverse_match (3).
//! CIDR contains packed IPv4/IPv6 bytes (1) and prefix length (2).

use crate::country_index::{CountryIndex, CountryRanges};
use crate::geodata_wire::PbReader;
use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpRange;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// Load all countries, or only the case-insensitive country allowlist.
/// Inverse entries are compiled to complementary ranges once, preserving the
/// rule engine's shared range index and allocation-free matching path.
pub fn from_dat_bytes(
    data: &[u8],
    allowed: Option<&HashSet<String>>,
) -> Result<CountryIndex, String> {
    parse(data, allowed).map_err(|error| format!("geoip.dat: {error}"))
}

fn parse(
    data: &[u8],
    allowed: Option<&HashSet<String>>,
) -> Result<CountryIndex, Box<dyn std::error::Error>> {
    let mut list = PbReader::new(data);
    let mut countries = HashMap::new();
    let mut entries = 0;
    while !list.is_at_end() {
        let (field, wire) = list.read_tag()?;
        if (field, wire) != (1, 2) {
            list.skip_field(wire)?;
            continue;
        }
        let bytes = list.read_length_delimited()?;
        let mut entry = PbReader::new(bytes);
        let mut country = "";
        let mut inverse = false;
        while !entry.is_at_end() {
            match entry.read_tag()? {
                (1, 2) => country = std::str::from_utf8(entry.read_length_delimited()?)?,
                (3, 0) => inverse = entry.read_varint()? != 0,
                (_, wire) => entry.skip_field(wire)?,
            }
        }
        if country.is_empty() {
            return Err("empty country code".into());
        }
        entries += 1;
        if allowed.is_some_and(|set| !set.iter().any(|key| key.eq_ignore_ascii_case(country))) {
            continue;
        }
        let mut v4 = IpRange::new();
        let mut v6 = IpRange::new();
        let mut entry = PbReader::new(bytes);
        while !entry.is_at_end() {
            match entry.read_tag()? {
                (2, 2) => {
                    let mut cidr = PbReader::new(entry.read_length_delimited()?);
                    let mut address = &[][..];
                    let mut prefix = 0;
                    while !cidr.is_at_end() {
                        match cidr.read_tag()? {
                            (1, 2) => address = cidr.read_length_delimited()?,
                            (2, 0) => prefix = u8::try_from(cidr.read_varint()?)?,
                            (_, wire) => cidr.skip_field(wire)?,
                        }
                    }
                    match address.len() {
                        4 => {
                            v4.add(Ipv4Net::new(
                                Ipv4Addr::from(<[u8; 4]>::try_from(address)?),
                                prefix,
                            )?);
                        }
                        16 => {
                            v6.add(Ipv6Net::new(
                                Ipv6Addr::from(<[u8; 16]>::try_from(address)?),
                                prefix,
                            )?);
                        }
                        _ => return Err("CIDR address must contain 4 or 16 bytes".into()),
                    }
                }
                (_, wire) => entry.skip_field(wire)?,
            }
        }
        if inverse {
            let all4: IpRange<Ipv4Net> = ["0.0.0.0/0".parse()?].into_iter().collect();
            let all6: IpRange<Ipv6Net> = ["::/0".parse()?].into_iter().collect();
            v4 = all4.exclude(&v4);
            v6 = all6.exclude(&v6);
        }
        v4.simplify();
        v6.simplify();
        countries
            .entry(country.to_ascii_uppercase())
            .or_insert(CountryRanges {
                v4: Arc::new(v4),
                v6: Arc::new(v6),
            });
    }
    if entries == 0 {
        return Err("database contains no GeoIP entries".into());
    }
    Ok(CountryIndex::from_ranges(countries))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_v4_v6_inverse_and_filters_unused_countries() {
        // Two independently encoded protobuf records, including unknown fields.
        let ordinary = [
            0x0a, 2, b'C', b'N', 0x12, 8, 0x0a, 4, 192, 0, 2, 0, 0x10, 24, 0x12, 20, 0x0a, 16,
            0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 32,
        ];
        let mut inverse = ordinary.to_vec();
        inverse[2..4].copy_from_slice(b"US");
        inverse.extend_from_slice(&[0x18, 1, 0x20, 17]);
        let mut data = vec![0x0a, ordinary.len() as u8];
        data.extend_from_slice(&ordinary);
        data.extend_from_slice(&[0x0a, inverse.len() as u8]);
        data.extend_from_slice(&inverse);
        let all = from_dat_bytes(&data, None).unwrap();
        assert!(all
            .ranges_for("cn")
            .v4
            .contains(&"192.0.2.9/32".parse::<Ipv4Net>().unwrap()));
        assert!(all
            .ranges_for("CN")
            .v6
            .contains(&"2001:db8::1/128".parse::<Ipv6Net>().unwrap()));
        assert!(!all
            .ranges_for("US")
            .v4
            .contains(&"192.0.2.9/32".parse::<Ipv4Net>().unwrap()));
        assert!(all
            .ranges_for("US")
            .v6
            .contains(&"2001:db9::1/128".parse::<Ipv6Net>().unwrap()));
        let selected = from_dat_bytes(&data, Some(&HashSet::from(["cn".into()]))).unwrap();
        assert_eq!(selected.country_count(), 1);
        assert!(selected.ranges_for("US").is_empty());
        for end in 1..ordinary.len() + 2 {
            assert!(from_dat_bytes(&data[..end], None).is_err());
        }
        assert!(from_dat_bytes(&[], None).is_err());
        let mut invalid_prefix = data.clone();
        invalid_prefix[15] = 33;
        assert!(from_dat_bytes(&invalid_prefix, None).is_err());
    }
}
