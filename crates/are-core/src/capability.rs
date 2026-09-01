//! Capability model for environment authorization.
//!
//! Capabilities represent discrete permissions that can be granted to clients.
//! Each capability is a single, non-overlapping authorization — for example,
//! `filesystem.read` is distinct from `filesystem.write`.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::CoreError;

/// A discrete permission that can be granted for an environment.
///
/// Serialized as lowercase dot-separated strings (e.g. `"filesystem.read"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Capability {
    FilesystemRead,
    FilesystemWrite,
    FilesystemList,
    ProcessExecute,
    ProcessInspect,
    ProcessTerminate,
}

impl Capability {
    /// Return the canonical dot-notation string for this capability.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FilesystemRead => "filesystem.read",
            Self::FilesystemWrite => "filesystem.write",
            Self::FilesystemList => "filesystem.list",
            Self::ProcessExecute => "process.execute",
            Self::ProcessInspect => "process.inspect",
            Self::ProcessTerminate => "process.terminate",
        }
    }

    /// Parse a capability from its string representation.
    pub fn parse_str(s: &str) -> Result<Self, CoreError> {
        match s {
            "filesystem.read" => Ok(Self::FilesystemRead),
            "filesystem.write" => Ok(Self::FilesystemWrite),
            "filesystem.list" => Ok(Self::FilesystemList),
            "process.execute" => Ok(Self::ProcessExecute),
            "process.inspect" => Ok(Self::ProcessInspect),
            "process.terminate" => Ok(Self::ProcessTerminate),
            _ => Err(CoreError::InvalidCapability(s.to_owned())),
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Capability {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse_str(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// CapabilitySet
// ---------------------------------------------------------------------------

/// An unordered set of capabilities granted to a client.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapabilitySet(HashSet<Capability>);

impl CapabilitySet {
    /// Create an empty capability set.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns `true` if the set contains the given capability.
    pub fn contains(&self, cap: &Capability) -> bool {
        self.0.contains(cap)
    }

    /// Returns `true` if every capability in `required` is present in `self`.
    pub fn grants(&self, required: &CapabilitySet) -> bool {
        required.is_subset(self)
    }

    /// Returns `true` if every capability in `self` is present in `other`.
    pub fn is_subset(&self, other: &CapabilitySet) -> bool {
        self.0.is_subset(&other.0)
    }

    /// Insert a capability into the set.
    pub fn insert(&mut self, cap: Capability) {
        self.0.insert(cap);
    }

    /// Return the number of capabilities in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over the capabilities in the set.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.0.iter()
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn capability_as_str_roundtrip() {
        let cases = [
            (Capability::FilesystemRead, "filesystem.read"),
            (Capability::FilesystemWrite, "filesystem.write"),
            (Capability::FilesystemList, "filesystem.list"),
            (Capability::ProcessExecute, "process.execute"),
            (Capability::ProcessInspect, "process.inspect"),
            (Capability::ProcessTerminate, "process.terminate"),
        ];
        for (cap, expected) in cases {
            assert_eq!(cap.as_str(), expected);
            assert_eq!(Capability::parse_str(expected).unwrap(), cap);
        }
    }

    #[test]
    fn capability_from_str_invalid() {
        assert!(Capability::parse_str("unknown.cap").is_err());
        assert!(Capability::parse_str("").is_err());
        assert!(Capability::parse_str("filesystem.read.write").is_err());
    }

    #[test]
    fn capability_display() {
        assert_eq!(format!("{}", Capability::FilesystemRead), "filesystem.read");
    }

    #[test]
    fn capability_serde_roundtrip() {
        let caps = [
            Capability::FilesystemRead,
            Capability::ProcessExecute,
            Capability::ProcessTerminate,
        ];
        for cap in &caps {
            let json = serde_json::to_string(cap).unwrap();
            assert_eq!(json, format!("\"{}\"", cap.as_str()));
            let back: Capability = serde_json::from_str(&json).unwrap();
            assert_eq!(*cap, back);
        }
    }

    #[test]
    fn capability_set_empty() {
        let set = CapabilitySet::empty();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn capability_set_contains() {
        let mut set = CapabilitySet::empty();
        set.insert(Capability::FilesystemRead);
        assert!(set.contains(&Capability::FilesystemRead));
        assert!(!set.contains(&Capability::FilesystemWrite));
    }

    #[test]
    fn capability_set_grants() {
        let mut granted = CapabilitySet::empty();
        granted.insert(Capability::FilesystemRead);
        granted.insert(Capability::FilesystemWrite);

        let mut required = CapabilitySet::empty();
        required.insert(Capability::FilesystemRead);

        assert!(granted.grants(&required));

        required.insert(Capability::ProcessExecute);
        assert!(!granted.grants(&required));
    }

    #[test]
    fn capability_set_is_subset() {
        let mut a = CapabilitySet::empty();
        a.insert(Capability::FilesystemRead);

        let mut b = CapabilitySet::empty();
        b.insert(Capability::FilesystemRead);
        b.insert(Capability::FilesystemWrite);

        assert!(a.is_subset(&b));
        assert!(!b.is_subset(&a));
    }

    #[test]
    fn capability_set_from_iter() {
        let set: CapabilitySet = [Capability::FilesystemRead, Capability::ProcessExecute]
            .into_iter()
            .collect();
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Capability::FilesystemRead));
        assert!(set.contains(&Capability::ProcessExecute));
    }

    #[test]
    fn capability_set_serde_roundtrip() {
        let mut set = CapabilitySet::empty();
        set.insert(Capability::FilesystemRead);
        set.insert(Capability::ProcessTerminate);

        let json = serde_json::to_string(&set).unwrap();
        let back: CapabilitySet = serde_json::from_str(&json).unwrap();
        assert_eq!(set, back);
    }
}
