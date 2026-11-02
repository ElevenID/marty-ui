//! Closed source adapter for the one immutable generation transaction. The
//! selected binding and authenticated plan agree before any producer action.
use super::*;
use crate::{
    installer_compose::{BoundFile, ComposeInputs},
    installer_managed_renewal::{self, ManagedRenewalPlan},
    installer_public_ingress::{self, PublicIngressPlan, PublicRenewalAuthorityPlan},
    installer_state::RuntimeBinding,
};
use std::collections::BTreeSet;

pub(crate) const MANAGED_LAYER: &str =
    "deploy-config/compose/selfhost-installer/compose.generation-managed.yml";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlanSource {
    Public,
    Managed,
}

#[derive(Clone)]
pub(crate) enum GenerationPlan {
    Public(Box<PublicIngressPlan>),
    Managed(Box<ManagedRenewalPlan>),
}
impl GenerationPlan {
    pub(crate) fn source(&self) -> PlanSource {
        match self {
            Self::Public(_) => PlanSource::Public,
            Self::Managed(_) => PlanSource::Managed,
        }
    }
    pub(crate) fn public(&self) -> Option<&PublicIngressPlan> {
        match self {
            Self::Public(value) => Some(value),
            Self::Managed(_) => None,
        }
    }
    pub(crate) fn managed(&self) -> Option<&ManagedRenewalPlan> {
        match self {
            Self::Public(_) => None,
            Self::Managed(value) => Some(value),
        }
    }
    pub(crate) fn load(
        installation: &Path,
        scope: Attempt,
        source: PlanSource,
        expected: &str,
    ) -> Result<Self> {
        require(valid_hash(expected))?;
        let kind = match source {
            PlanSource::Public => "public-ingress-plan",
            PlanSource::Managed => "managed-renewal-plan",
        };
        let bytes = read(installation, &scope.record(kind))?;
        let plan = match source {
            PlanSource::Public => Self::Public(Box::new(PublicIngressPlan::parse_authenticated(
                &bytes, expected,
            )?)),
            PlanSource::Managed => Self::Managed(Box::new(
                ManagedRenewalPlan::parse_authenticated(&bytes, expected)?,
            )),
        };
        require(plan.record_name() == scope.record(kind))?;
        let opposite = match source {
            PlanSource::Public => "managed-renewal-plan",
            PlanSource::Managed => "public-ingress-plan",
        };
        require(optional(installation, &scope.record(opposite))?.is_none())?;
        Ok(plan)
    }
    pub(crate) fn from_public(
        view: &LockedInspection,
        installation: &Path,
        candidate: &AcmeCandidate,
        parent: &GenerationBinding,
        attempt: u64,
    ) -> Result<Self> {
        require(parent.public_ingress())?;
        Ok(Self::Public(Box::new(
            PublicIngressPlan::from_successor_attempt(
                view,
                installation,
                candidate,
                parent,
                attempt,
            )?,
        )))
    }
    pub(crate) fn from_managed(
        view: &LockedInspection,
        installation: &Path,
        parent: &GenerationBinding,
        attempt: u64,
    ) -> Result<Self> {
        require(parent.managed_ingress())?;
        Ok(Self::Managed(Box::new(ManagedRenewalPlan::from_selected(
            view,
            installation,
            parent,
            attempt,
        )?)))
    }
    pub(crate) fn record_name(&self) -> String {
        match self {
            Self::Public(value) => value.record_name(),
            Self::Managed(value) => value.record_name(),
        }
    }
    pub(crate) fn plan_kind(&self) -> &'static str {
        match self {
            Self::Public(_) => "public-ingress-plan",
            Self::Managed(_) => "managed-renewal-plan",
        }
    }
    pub(crate) fn sha256(&self) -> Result<String> {
        match self {
            Self::Public(value) => value.sha256(),
            Self::Managed(value) => value.sha256(),
        }
    }
    pub(crate) fn record_for_maintenance(&self, state: &mut LockedMaintenance) -> Result<PathBuf> {
        match self {
            Self::Public(value) => value.record_for_maintenance(state),
            Self::Managed(value) => value.record_for_maintenance(state),
        }
    }
    pub(crate) fn require_saved(&self, view: &LockedInspection) -> Result<()> {
        match self {
            Self::Public(value) => value.require_saved(view),
            Self::Managed(value) => value.require_saved(view),
        }
    }
    pub(crate) fn require_parent(
        &self,
        installation: &Path,
        parent: &GenerationBinding,
    ) -> Result<()> {
        require(match self.source() {
            PlanSource::Public => parent.public_ingress(),
            PlanSource::Managed => parent.managed_ingress(),
        })?;
        match self {
            Self::Public(value) => value.require_parent(installation, parent),
            Self::Managed(value) => value.require_parent(installation, parent),
        }
    }
    pub(crate) fn require_verified_parent(
        &self,
        installation: &Path,
        parent: &generation::VerifiedGeneration,
    ) -> Result<()> {
        match self {
            Self::Public(value) => value.require_verified_parent(installation, parent),
            Self::Managed(value) => value.require_verified_parent(
                installation,
                parent.binding(),
                parent.managed_metadata().ok_or(REFUSED)?,
            ),
        }
    }
    pub(crate) fn inputs(&self) -> BTreeSet<String> {
        match self {
            Self::Public(_) => crate::installer_renewal_bootstrap::public_inputs(),
            Self::Managed(_) => crate::installer_renewal_bootstrap::managed_inputs(),
        }
    }
    pub(crate) fn layer(&self) -> (&'static str, &'static [u8]) {
        match self {
            Self::Public(_) => (LAYER, include_bytes!("../../../../deploy-config/compose/selfhost-installer/compose.generation.yml")),
            Self::Managed(_) => (MANAGED_LAYER, include_bytes!("../../../../deploy-config/compose/selfhost-installer/compose.generation-managed.yml")),
        }
    }
    pub(crate) fn environment(
        &self,
        installation: &Path,
    ) -> Result<BTreeMap<&'static str, String>> {
        let path = installation.join("evidence").join(self.record_name());
        let path = path.to_str().ok_or(REFUSED)?.to_owned();
        Ok(match self {
            Self::Public(value) => BTreeMap::from([
                ("MARTY_GENERATION_PUBLIC_INGRESS_PLAN", path),
                (installer_public_ingress::PLAN_DIGEST_ENV, value.sha256()?),
                (
                    installer_public_ingress::AUTHORITY_PLAN_DIGEST_ENV,
                    value.renewal_authority_plan_sha256().into(),
                ),
            ]),
            Self::Managed(value) => BTreeMap::from([
                ("MARTY_GENERATION_MANAGED_RENEWAL_PLAN", path),
                (installer_managed_renewal::PLAN_DIGEST_ENV, value.sha256()?),
            ]),
        })
    }
    pub(crate) fn bind_inputs(
        &self,
        installation: &Path,
        inputs: &mut ComposeInputs,
    ) -> Result<()> {
        inputs.bound_inputs.retain(|file| {
            !file
                .path
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|name| {
                    name.starts_with("generation-")
                        && (name.ends_with("public-ingress-plan.json")
                            || name.ends_with("managed-renewal-plan.json"))
                })
        });
        inputs.bound_inputs.push(BoundFile {
            path: installation.join("evidence").join(self.record_name()),
            sha256: self.sha256()?,
        });
        if let Self::Public(value) = self {
            let path = installation
                .join("evidence")
                .join(installer_public_ingress::PUBLIC_RENEWAL_AUTHORITY_PLAN_RECORD);
            if !inputs.bound_inputs.iter().any(|file| file.path == path) {
                inputs.bound_inputs.push(BoundFile {
                    path,
                    sha256: value.renewal_authority_plan_sha256().into(),
                });
            }
        }
        Ok(())
    }
    pub(crate) fn require_enrolment(
        &self,
        view: &LockedInspection,
        installation: &Path,
    ) -> Result<()> {
        match self {
            Self::Public(_) => {
                let authority = PublicRenewalAuthorityPlan::load(view)?;
                crate::installer_renewal::require_public_enrolment(view, &authority).map(|_| ())
            }
            Self::Managed(_) => {
                crate::installer_renewal::require_managed_enrolment(view, installation).map(|_| ())
            }
        }
    }
    pub(crate) fn require_job_inputs(
        &self,
        docker: &Path,
        runtime: &RuntimeBinding,
        inputs: &ComposeInputs,
    ) -> Result<()> {
        match self {
            Self::Public(value) => {
                value.require_job_inputs(docker, runtime, inputs, "installer-generation")
            }
            Self::Managed(value) => value.require_job_inputs(docker, runtime, inputs),
        }
    }
    pub(crate) fn validate_before_producer(
        &self,
        installation: &Path,
        parent: &GenerationBinding,
        at: u64,
    ) -> Result<()> {
        self.require_parent(installation, parent)?;
        match self {
            Self::Public(value) => value.validate_current_certificate().map(|_| ()),
            Self::Managed(_) => super::material::GenerationMaterial::load(installation, parent)?
                .require_issuer_lifetime(installation, parent, at),
        }
    }
}
