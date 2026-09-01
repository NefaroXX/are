//! Platform identification for remote environments.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Identifies the operating system or environment type of a remote machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    /// Debian Linux.
    Debian,
    /// Ubuntu Linux.
    Ubuntu,
    /// Generic Linux distribution (not Debian or Ubuntu).
    GenericLinux,
    /// Unknown or unrecognized platform, carrying the raw identifier.
    Unknown(String),
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Debian => f.write_str("Debian"),
            Self::Ubuntu => f.write_str("Ubuntu"),
            Self::GenericLinux => f.write_str("Generic Linux"),
            Self::Unknown(s) => write!(f, "Unknown ({s})"),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn platform_display() {
        assert_eq!(format!("{}", Platform::Debian), "Debian");
        assert_eq!(format!("{}", Platform::Ubuntu), "Ubuntu");
        assert_eq!(format!("{}", Platform::GenericLinux), "Generic Linux");
        assert_eq!(
            format!("{}", Platform::Unknown("alpine".into())),
            "Unknown (alpine)"
        );
    }

    #[test]
    fn platform_serde_roundtrip() {
        let platforms = [
            Platform::Debian,
            Platform::Ubuntu,
            Platform::GenericLinux,
            Platform::Unknown("nixos".into()),
        ];
        for p in &platforms {
            let json = serde_json::to_string(p).unwrap();
            let back: Platform = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, back);
        }
    }
}
