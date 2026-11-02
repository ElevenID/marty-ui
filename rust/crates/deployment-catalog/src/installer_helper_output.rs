//! Host ownership expected for files written by a one-shot container UID 0.
//! This is a narrow acceptance rule, not proof of the daemon's full UID map.
#![cfg(target_os = "linux")]

use crate::installer_state::{RuntimeBinding, RuntimeProfile};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
