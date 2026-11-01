//! One immutable producer/activation attempt within a contiguous selected
//! generation. Attempt zero retains the original published names and bytes.
use std::path::{Path, PathBuf};

pub(crate) fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Attempt {
    pub(crate) sequence: u64,
    pub(crate) number: u64,
}

impl Attempt {
    pub(crate) const fn new(sequence: u64, number: u64) -> Self {
        Self { sequence, number }
    }

    pub(crate) fn record(self, kind: &str) -> String {
        if self.number == 0 {
            format!("generation-{:020}-{kind}.json", self.sequence)
        } else {
            format!(
                "generation-{:020}-attempt-{:020}-{kind}.json",
                self.sequence, self.number
            )
        }
    }

    pub(crate) fn operation_prefix(self) -> String {
        if self.number == 0 {
            format!("g{:020}", self.sequence)
        } else {
            format!("g{:020}-a{:020}", self.sequence, self.number)
        }
    }

    pub(crate) fn operation(self, phase: &str, ordinal: u64) -> String {
        format!("{}-{phase}-{ordinal:06}", self.operation_prefix())
    }

    pub(crate) fn work(self, installation: &Path) -> PathBuf {
        let root = installation
            .join("generation-work")
            .join(format!("{:020}", self.sequence));
        if self.number == 0 {
            root
        } else {
            root.join(format!("attempt-{:020}", self.number))
        }
    }

    pub(crate) fn environment_name(self, role: &str) -> String {
        self.record(role).replace(".json", ".env")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_zero_keeps_published_paths_and_successors_never_alias() {
        let original = Attempt::new(1, 0);
        assert_eq!(
            original.record("binding"),
            "generation-00000000000000000001-binding.json"
        );
        assert_eq!(
            original.operation("start", 0),
            "g00000000000000000001-start-000000"
        );
        assert_eq!(
            original.work(Path::new("/installation")),
            Path::new("/installation/generation-work/00000000000000000001")
        );
        let replacement = Attempt::new(1, 1);
        assert_ne!(replacement.record("binding"), original.record("binding"));
        assert_ne!(
            replacement.operation("start", 0),
            original.operation("start", 0)
        );
        assert_ne!(
            replacement.work(Path::new("/installation")),
            original.work(Path::new("/installation"))
        );
        assert!(replacement.record("activation-intent").len() < 128);
        assert!(replacement.operation("activate-create", 999_999).len() < 96);
    }
}
