//! Host ownership expected for files written by a one-shot container UID 0.
//! This is a narrow acceptance rule, not proof of the daemon's full UID map.
#![cfg(target_os = "linux")]

use crate::installer_state::{RuntimeBinding, RuntimeProfile};
use std::{fs::File, os::unix::fs::MetadataExt};

#[derive(Clone, Copy)]
pub(crate) struct HelperOutputOwner(u32);

impl HelperOutputOwner {
    pub(crate) fn uid(self) -> u32 {
        self.0
    }
}

pub(crate) fn expected_host_uid(binding: &RuntimeBinding) -> Result<HelperOutputOwner, String> {
    binding.validate()?;
    match binding.profile {
        RuntimeProfile::Rootful => Ok(HelperOutputOwner(0)),
        RuntimeProfile::Rootless => {
            // RuntimeBinding::validate pins the persisted rootless profile to the
            // caller's exact per-user socket. DockerRunner::from_binding holds
            // that socket and positively checks rootless Engine policy before
            // the helper starts. Refuse any subordinate/unknown output owner.
            let uid = unsafe { libc::geteuid() };
            if uid == 0 {
                return Err("rootless helper output requires a nonroot installer".into());
            }
            Ok(HelperOutputOwner(uid))
        }
    }
}

/// Validate the fixed producer-owned entries without reading or repairing them.
/// The caller retains its stage refusal and delivery/inventory policy.
pub(crate) fn validate_retained_entries(
    held: &File,
    expected_host_uid: HelperOutputOwner,
    refusal: &str,
) -> Result<(), String> {
    for (name, is_dir, mode) in [
        ("output", true, 0o700),
        ("transfer-pending.json", false, 0o600),
    ] {
        let m = crate::installer_host_fs::open_child(held, name, libc::O_PATH, refusal)?
            .metadata()
            .map_err(|_| refusal)?;
        let accepted = !m.file_type().is_symlink()
            && m.is_dir() == is_dir
            && (is_dir || (m.is_file() && m.nlink() == 1))
            && m.uid() == expected_host_uid.uid()
            && m.mode() & 0o7777 == mode;
        if !accepted {
            return Err(refusal.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::CString, os::unix::fs::PermissionsExt};

    fn binding(profile: RuntimeProfile, host: String) -> RuntimeBinding {
        RuntimeBinding {
            docker_host: host,
            engine_id: "engine-identity-123".into(),
            openbao_port: 8200,
            profile,
        }
    }

    #[test]
    fn legacy_rootful_owner_remains_zero() {
        let b = binding(
            RuntimeProfile::Rootful,
            "unix:///var/run/docker.sock".into(),
        );
        assert_eq!(expected_host_uid(&b).unwrap().uid(), 0);
    }

    #[test]
    fn rootless_owner_requires_exact_persisted_user_socket() {
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            return;
        }
        let b = binding(
            RuntimeProfile::Rootless,
            format!("unix:///run/user/{uid}/docker.sock"),
        );
        assert_eq!(expected_host_uid(&b).unwrap().uid(), uid);
        assert!(expected_host_uid(&binding(
            RuntimeProfile::Rootless,
            "unix:///var/run/docker.sock".into(),
        ))
        .is_err());
        assert!(expected_host_uid(&binding(
            RuntimeProfile::Rootless,
            format!("unix:///run/user/{}/docker.sock", uid + 1),
        ))
        .is_err());
    }

    #[test]
    fn retained_entries_reject_missing_and_fifo_inputs_with_stage_refusals() {
        let uid = unsafe { libc::geteuid() };
        let owner = if uid == 0 {
            expected_host_uid(&binding(
                RuntimeProfile::Rootful,
                "unix:///var/run/docker.sock".into(),
            ))
        } else {
            expected_host_uid(&binding(
                RuntimeProfile::Rootless,
                format!("unix:///run/user/{uid}/docker.sock"),
            ))
        }
        .unwrap();
        for refusal in ["generation-stage-refusal", "renewal-stage-refusal"] {
            for mutation in ["missing-output", "missing-pending", "fifo-pending"] {
                let temp = tempfile::tempdir().unwrap();
                let output = temp.path().join("output");
                let pending = temp.path().join("transfer-pending.json");
                std::fs::create_dir(&output).unwrap();
                std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).unwrap();
                std::fs::write(&pending, b"retained producer evidence").unwrap();
                std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o600)).unwrap();
                let held = File::open(temp.path()).unwrap();
                validate_retained_entries(&held, owner, refusal).unwrap();
                match mutation {
                    "missing-output" => std::fs::remove_dir(&output).unwrap(),
                    "missing-pending" => std::fs::remove_file(&pending).unwrap(),
                    "fifo-pending" => {
                        std::fs::remove_file(&pending).unwrap();
                        let name = CString::new(pending.to_str().unwrap()).unwrap();
                        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                    }
                    _ => unreachable!(),
                }
                assert_eq!(
                    validate_retained_entries(&held, owner, refusal).unwrap_err(),
                    refusal,
                    "accepted {mutation}"
                );
                if mutation != "missing-output" {
                    assert!(output.is_dir());
                }
            }
        }
    }
}
