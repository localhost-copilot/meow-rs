//! A compact, read-only domain trie for large data files.
//!
//! [`DomainTrie`] is a good general purpose builder and matcher, but its
//! sealed representation keeps one boxed child slice per node. GeoSite files
//! contain hundreds of thousands of entries, so that per-node allocation and
//! slice metadata become material. `CompactDomainTrie` stores all nodes, edges,
//! and label bytes in contiguous vectors after construction. Matching remains
//! a suffix walk with binary search over a node's sorted edges.

use std::collections::HashMap;

#[derive(Clone, Copy, Default)]
struct Node {
    first_edge: u32,
    edge_count: u32,
    exact: bool,
    star: bool,
    dot: bool,
}

#[derive(Clone, Copy)]
struct Edge {
    label_offset: u32,
    label_len: u32,
    child: u32,
}

struct BuildNode {
    children: HashMap<Box<str>, usize>,
    exact: bool,
    star: bool,
    dot: bool,
}

impl BuildNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            exact: false,
            star: false,
            dot: false,
        }
    }
}

/// A compact immutable suffix trie supporting the same domain forms as
/// [`DomainTrie`](super::DomainTrie): exact names, `*.` wildcards, `.` suffixes
/// and `+.` entries that provide both wildcard forms.
pub struct CompactDomainTrie {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    labels: Vec<u8>,
    len: usize,
    /// Present only for a programmatically built trie. File-backed GeoSite
    /// instances are converted to the compact vectors above before exposure.
    building: Option<Vec<BuildNode>>,
}

impl CompactDomainTrie {
    /// Build and seal a compact trie from domain patterns.
    pub fn from_patterns<'a>(patterns: impl IntoIterator<Item = &'a str>) -> Self {
        let mut building = vec![BuildNode::new()];
        let mut len = 0;
        for pattern in patterns {
            len += usize::from(insert_building(&mut building, pattern));
        }

        let mut compact = Self {
            nodes: Vec::with_capacity(building.len()),
            edges: Vec::new(),
            labels: Vec::new(),
            len,
            building: None,
        };
        compact.emit(0, &mut building);
        compact
    }

    fn emit(&mut self, source: usize, building: &mut [BuildNode]) -> u32 {
        let index = self.nodes.len() as u32;
        self.nodes.push(Node::default());
        let exact = building[source].exact;
        let star = building[source].star;
        let dot = building[source].dot;
        let mut children: Vec<(Box<str>, usize)> = std::mem::take(&mut building[source].children)
            .into_iter()
            .collect();
        children.sort_unstable_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
        let mut emitted = Vec::with_capacity(children.len());
        for (label, child) in children {
            let child_index = self.emit(child, building);
            let offset = self.labels.len() as u32;
            self.labels.extend_from_slice(label.as_bytes());
            emitted.push(Edge {
                label_offset: offset,
                label_len: label.len() as u32,
                child: child_index,
            });
        }
        let first_edge = self.edges.len() as u32;
        let edge_count = emitted.len() as u32;
        self.edges.extend(emitted);
        self.nodes[index as usize] = Node {
            first_edge,
            edge_count,
            exact,
            star,
            dot,
        };
        index
    }

    /// Number of patterns accepted by the builder. Duplicate patterns are
    /// counted just like [`super::DomainTrie::insert`] counts them.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Insert a pattern into an existing compact trie. This is intended for
    /// the small programmatic `GeositeDB::insert` API; file-backed GeoSite
    /// databases are built once and never take this path. Rebuilding keeps the
    /// steady-state representation compact and avoids retaining a mutable
    /// hash-map tree in every loaded database.
    pub fn insert(&mut self, pattern: &str) -> bool {
        if let Some(building) = &mut self.building {
            if insert_building(building, pattern) {
                self.len += 1;
                return true;
            }
            return false;
        }
        let mut patterns = Vec::new();
        let mut labels = Vec::new();
        self.collect_patterns(0, &mut labels, &mut patterns);
        patterns.push(pattern.to_owned());
        *self = Self::from_patterns(patterns.iter().map(String::as_str));
        true
    }

    fn collect_patterns(&self, index: usize, labels: &mut Vec<String>, out: &mut Vec<String>) {
        let node = self.nodes[index];
        let name = labels
            .iter()
            .rev()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(".");
        if !name.is_empty() {
            if node.exact {
                out.push(name.clone());
            }
            if node.star {
                out.push(format!("*.{name}"));
            }
            if node.dot {
                out.push(format!(".{name}"));
            }
        }
        let edges =
            &self.edges[node.first_edge as usize..(node.first_edge + node.edge_count) as usize];
        for edge in edges {
            labels.push(String::from_utf8_lossy(self.edge_label(edge)).into_owned());
            self.collect_patterns(edge.child as usize, labels, out);
            labels.pop();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Match a domain, accepting ASCII case differences and a trailing dot.
    pub fn search(&self, domain: &str) -> bool {
        let trimmed = domain.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return false;
        }
        if trimmed.bytes().any(|byte| byte.is_ascii_uppercase()) {
            if let Some(building) = &self.building {
                search_building(building, trimmed, true)
            } else {
                self.search_case_insensitive(trimmed)
            }
        } else {
            self.search_normalized(trimmed)
        }
    }

    /// Match a pre-lowercased domain without allocating.
    pub fn search_normalized(&self, domain: &str) -> bool {
        let query = domain.trim_end_matches('.');
        if query.is_empty() || self.is_empty() {
            return false;
        }
        if let Some(building) = &self.building {
            return search_building(building, query, false);
        }
        self.walk(query, |label, edge| {
            self.edge_label(edge).cmp(label.as_bytes())
        })
    }

    fn search_case_insensitive(&self, domain: &str) -> bool {
        self.walk(domain, |label, edge| {
            cmp_ascii_lower_to_mixed(self.edge_label(edge), label.as_bytes())
        })
    }

    fn walk(
        &self,
        query: &str,
        mut compare: impl FnMut(&str, &Edge) -> std::cmp::Ordering,
    ) -> bool {
        let label_count = query.bytes().filter(|&byte| byte == b'.').count() + 1;
        let mut node_index = 0usize;
        let mut best = false;
        for (depth, label) in query.rsplit('.').enumerate() {
            let node = self.nodes[node_index];
            let edges =
                &self.edges[node.first_edge as usize..(node.first_edge + node.edge_count) as usize];
            let found = edges.binary_search_by(|edge| compare(label, edge));
            let Ok(edge_index) = found else { break };
            node_index = edges[edge_index].child as usize;
            let child = self.nodes[node_index];
            let remaining = label_count - depth - 1;
            if remaining == 0 {
                if child.exact {
                    return true;
                }
            } else if remaining == 1 {
                best |= child.star || child.dot;
            } else if child.dot {
                best = true;
            }
        }
        best
    }

    fn edge_label(&self, edge: &Edge) -> &[u8] {
        &self.labels[edge.label_offset as usize..(edge.label_offset + edge.label_len) as usize]
    }
}

impl Default for CompactDomainTrie {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            labels: Vec::new(),
            len: 0,
            building: Some(vec![BuildNode::new()]),
        }
    }
}

fn insert_building(building: &mut Vec<BuildNode>, pattern: &str) -> bool {
    let domain = pattern.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return false;
    }
    let (base, kind) = if let Some(rest) = domain.strip_prefix("+.") {
        (rest, MatchKind::Both)
    } else if let Some(rest) = domain.strip_prefix("*.") {
        (rest, MatchKind::Star)
    } else if let Some(rest) = domain.strip_prefix('.') {
        (rest, MatchKind::Dot)
    } else {
        (domain.as_str(), MatchKind::Exact)
    };
    if base.is_empty() {
        return false;
    }
    let mut node = 0;
    for label in base.rsplit('.') {
        let next = if let Some(&child) = building[node].children.get(label) {
            child
        } else {
            let child = building.len();
            building.push(BuildNode::new());
            building[node]
                .children
                .insert(label.to_owned().into_boxed_str(), child);
            child
        };
        node = next;
    }
    match kind {
        MatchKind::Exact => building[node].exact = true,
        MatchKind::Star => building[node].star = true,
        MatchKind::Dot => building[node].dot = true,
        MatchKind::Both => {
            building[node].star = true;
            building[node].dot = true;
        }
    }
    true
}

fn search_building(building: &[BuildNode], query: &str, case_insensitive: bool) -> bool {
    let label_count = query.bytes().filter(|&byte| byte == b'.').count() + 1;
    let mut node_index = 0usize;
    let mut best = false;
    for (depth, label) in query.rsplit('.').enumerate() {
        let node = &building[node_index];
        let child_index = if case_insensitive {
            node.children
                .iter()
                .find(|(key, _)| key.as_bytes().eq_ignore_ascii_case(label.as_bytes()))
                .map(|(_, child)| *child)
        } else {
            node.children.get(label).copied()
        };
        let Some(child_index) = child_index else {
            break;
        };
        node_index = child_index;
        let child = &building[node_index];
        let remaining = label_count - depth - 1;
        if remaining == 0 {
            if child.exact {
                return true;
            }
        } else if remaining == 1 {
            best |= child.star || child.dot;
        } else if child.dot {
            best = true;
        }
    }
    best
}

#[derive(Clone, Copy)]
enum MatchKind {
    Exact,
    Star,
    Dot,
    Both,
}

fn cmp_ascii_lower_to_mixed(lower: &[u8], mixed: &[u8]) -> std::cmp::Ordering {
    for (&a, &b) in lower.iter().zip(mixed.iter()) {
        match a.cmp(&b.to_ascii_lowercase()) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    lower.len().cmp(&mixed.len())
}

#[cfg(test)]
mod tests {
    use super::CompactDomainTrie;

    fn trie(patterns: &[&str]) -> CompactDomainTrie {
        CompactDomainTrie::from_patterns(patterns.iter().copied())
    }

    #[test]
    fn matches_domain_forms() {
        let trie = trie(&["example.com", "*.wild.test", ".suffix.test", "+.both.test"]);
        assert!(trie.search("example.com"));
        assert!(!trie.search("www.example.com"));
        assert!(trie.search("a.wild.test"));
        assert!(!trie.search("a.b.wild.test"));
        assert!(trie.search("a.suffix.test"));
        assert!(trie.search("a.b.suffix.test"));
        assert!(trie.search("a.both.test"));
        assert!(trie.search("a.b.both.test"));
        assert!(trie.search("EXAMPLE.COM."));
    }

    #[test]
    fn duplicate_and_empty_patterns_are_safe() {
        let trie = trie(&["", ".", "+.", "example.com", "example.com"]);
        assert_eq!(trie.len(), 2);
        assert!(trie.search("example.com"));
    }
}
