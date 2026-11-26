//! Persistent filesystem identity, separate from within-process inode guards.
//!
//! Linux device numbers can change after a cold boot. Fresh ext4 observations
//! bind the full filesystem UUID; historical numeric bindings remain strict.
//! This is not a legacy-receipt migration or authority to adopt another path.
#![cfg(target_os = "linux")]

use serde::{Deserialize, Serialize};
use std::{fs::File, os::fd::AsRawFd, os::unix::fs::MetadataExt};

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Schema {
    #[serde(rename = "elevenid.installer-filesystem/v2")]
    Ext4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StableDevice {
    schema: Schema,
    device: u64,
    ext4_uuid: [u8; 16],
}

/// The integer encoding is the original v1 device field, preserved byte for
/// byte on serialization. The explicit v2 object is only written for a fresh
/// successful UUID observation. Missing/unknown v2 fields cannot become v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub(crate) enum DeviceBinding {
    Legacy(u64),
    Stable(StableDevice),
}

impl<'de> Deserialize<'de> for DeviceBinding {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Encoded {
            Legacy(u64),
            Stable(StableDevice),
        }
        let value = match Encoded::deserialize(deserializer)? {
            Encoded::Legacy(device) => Self::Legacy(device),
            Encoded::Stable(value) => Self::Stable(value),
        };
        if value.valid() {
            Ok(value)
        } else {
            Err(serde::de::Error::custom(
                "invalid installer filesystem binding",
            ))
        }
    }
}

impl DeviceBinding {
    pub(crate) fn device(self) -> u64 {
        match self {
            Self::Legacy(device) => device,
            Self::Stable(value) => value.device,
        }
    }

    pub(crate) fn stable(self) -> Option<Self> {
        (matches!(self, Self::Stable(_)) && self.valid()).then_some(self)
    }

    fn valid(self) -> bool {
        self.device() != 0
            && match self {
                Self::Legacy(_) => true,
                Self::Stable(value) => value.ext4_uuid != [0; 16],
            }
    }

    /// Directional comparison against a retained binding. Do not use this for
    /// comparisons between two observations in one process: ordinary equality
    /// deliberately still includes the observed device number in those guards.
    pub(crate) fn matches(self, observed: Self) -> bool {
        self.valid()
            && observed.valid()
            && match (self, observed) {
                (Self::Legacy(device), current) => device == current.device(),
                (Self::Stable(saved), Self::Stable(current)) => {
                    saved.schema == current.schema && saved.ext4_uuid == current.ext4_uuid
                }
                (Self::Stable(_), Self::Legacy(_)) => false,
            }
    }

    pub(crate) fn matches_json(value: &serde_json::Value, observed: Self) -> bool {
        serde_json::from_value::<Self>(value.clone()).is_ok_and(|saved| saved.matches(observed))
    }

    /// Observe an already-held readable file/directory without reading its
    /// contents. An O_PATH-only private child must instead use `under` with a
    /// readable held parent on that same current filesystem.
    pub(crate) fn observe(file: &File, refusal: &str) -> Result<Self> {
        let before = file.metadata().map_err(|_| refusal)?;
        if before.dev() == 0 {
            return Err(refusal.into());
        }
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: the held descriptor and output structure outlive the call.
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0 {
            return Err(refusal.into());
        }
        let result = if filesystem.f_type as u64 == 0xef53 {
            observe_ext4_uuid(file, before.dev(), refusal)?
        } else {
            // Do not invent a stable identity for another filesystem. Its
            // existing exact-device behavior remains available and explicit.
            Self::Legacy(before.dev())
        };
        let after = file.metadata().map_err(|_| refusal)?;
        if before.dev() != after.dev() || before.ino() != after.ino() || !result.valid() {
            return Err(refusal.into());
        }
        Ok(result)
    }

    /// A parent's UUID is not evidence about a child on a different mount.
    /// Require actual current device equality before using the held anchor.
    pub(crate) fn under(anchor: &File, child: &std::fs::Metadata, refusal: &str) -> Result<Self> {
        let observed = Self::observe(anchor, refusal)?;
        if observed.device() != child.dev() {
            return Err(refusal.into());
        }
        Ok(observed)
    }

    #[cfg(test)]
    pub(crate) fn ext4_for_test(device: u64, ext4_uuid: [u8; 16]) -> Self {
        Self::Stable(StableDevice {
            schema: Schema::Ext4,
            device,
            ext4_uuid,
        })
    }
}

fn observe_ext4_uuid(file: &File, device: u64, refusal: &str) -> Result<DeviceBinding> {
    // Linux include/uapi/linux/ext4.h: _IOR('f', 44, struct fsuuid).
    // The UAPI structure has an eight-byte header and a flexible byte array;
    // the ioctl request size is therefore 8, not this buffer's total size 24.
    const GET_FS_UUID: u32 = 0x8008_662c;
    #[repr(C)]
    struct FsUuid {
        length: u32,
        flags: u32,
        uuid: [u8; 16],
    }
    let mut value = FsUuid {
        length: 16,
        flags: 0,
        uuid: [0; 16],
    };
    // SAFETY: this read-only ioctl receives the exact Linux UAPI header with
    // room for all 16 requested bytes. It neither reads file contents nor
    // changes the filesystem UUID and requires no elevated capability.
    let result = unsafe { libc::ioctl(file.as_raw_fd(), GET_FS_UUID as _, &mut value) };
    if result != 0 {
        return unsupported_uuid(
            std::io::Error::last_os_error().raw_os_error(),
            device,
            refusal,
        );
    }
    if value.length != 16 || value.flags != 0 || value.uuid == [0; 16] {
        return Err(refusal.into());
    }
    Ok(DeviceBinding::Stable(StableDevice {
        schema: Schema::Ext4,
        device,
        ext4_uuid: value.uuid,
    }))
}

fn unsupported_uuid(error: Option<i32>, device: u64, refusal: &str) -> Result<DeviceBinding> {
    match error {
        Some(libc::ENOTTY | libc::EOPNOTSUPP) => Ok(DeviceBinding::Legacy(device)),
        _ => Err(refusal.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn persistent_uuid_comparison_does_not_relax_legacy_or_live_device_guards() {
        let original = DeviceBinding::ext4_for_test(2160, [7; 16]);
        let rebooted = DeviceBinding::ext4_for_test(2096, [7; 16]);
        assert!(original.matches(rebooted));
        assert_ne!(
            original, rebooted,
            "same-process equality must remain exact"
        );
        assert!(!DeviceBinding::Legacy(2160).matches(rebooted));
        assert!(DeviceBinding::Legacy(2096).matches(rebooted));
        assert!(!original.matches(DeviceBinding::Legacy(2160)));
        assert!(!original.matches(DeviceBinding::ext4_for_test(2160, [8; 16])));
        assert!(!original.matches(DeviceBinding::ext4_for_test(2096, [0; 16])));
        assert!(!DeviceBinding::Legacy(0).matches(DeviceBinding::Legacy(0)));
    }

    #[test]
    fn legacy_encoding_is_unchanged_and_v2_cannot_downgrade_when_malformed() {
        let legacy: DeviceBinding = serde_json::from_str("2160").unwrap();
        assert_eq!(serde_json::to_string(&legacy).unwrap(), "2160");
        let current = DeviceBinding::ext4_for_test(2096, [7; 16]);
        let record = serde_json::to_value(current).unwrap();
        assert_eq!(record["schema"], "elevenid.installer-filesystem/v2");
        assert!(DeviceBinding::matches_json(&record, current));
        for key in ["schema", "device", "ext4_uuid"] {
            let mut missing = record.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(!DeviceBinding::matches_json(&missing, current));
        }
        for (field, bad) in [
            ("schema", json!("elevenid.installer-filesystem/v1")),
            ("ext4_uuid", json!(vec![7; 15])),
            ("ext4_uuid", json!(vec![0; 16])),
            ("device", json!(0)),
            ("device", json!("2096")),
            ("unknown", json!(true)),
        ] {
            let mut changed = record.clone();
            changed[field] = bad;
            assert!(!DeviceBinding::matches_json(&changed, current));
        }
    }

    #[test]
    fn held_anchor_cannot_lend_its_identity_to_a_different_filesystem() {
        let scratch = tempfile::tempdir().unwrap();
        let anchor = File::open(scratch.path()).unwrap();
        let foreign = std::fs::metadata("/proc").unwrap();
        assert_ne!(anchor.metadata().unwrap().dev(), foreign.dev());
        assert!(DeviceBinding::under(&anchor, &foreign, "refused").is_err());
        let same = anchor.metadata().unwrap();
        assert_eq!(
            DeviceBinding::under(&anchor, &same, "refused").unwrap(),
            DeviceBinding::observe(&anchor, "refused").unwrap()
        );
    }

    #[test]
    fn only_an_unsupported_ioctl_can_retain_legacy_capture() {
        for error in [libc::ENOTTY, libc::EOPNOTSUPP] {
            assert_eq!(
                unsupported_uuid(Some(error), 2160, "refused").unwrap(),
                DeviceBinding::Legacy(2160)
            );
        }
        for error in [
            Some(libc::EPERM),
            Some(libc::EACCES),
            Some(libc::EIO),
            Some(libc::EINVAL),
            Some(libc::EBADF),
            None,
        ] {
            assert_eq!(
                unsupported_uuid(error, 2160, "refused").unwrap_err(),
                "refused"
            );
        }
    }
}
