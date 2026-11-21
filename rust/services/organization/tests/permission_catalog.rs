use std::collections::BTreeSet;

use marty_organization::{
    catalog::{permission_catalog, system_role_templates},
    APPLICANT_PERMISSION_KEYS,
};

#[test]
fn shared_permission_catalog_is_unique_and_complete() {
    let catalog = permission_catalog().expect("shared permission catalog must parse");
    let keys: BTreeSet<_> = catalog.iter().map(|permission| permission.key()).collect();
    assert_eq!(catalog.len(), 139);
    assert_eq!(keys.len(), catalog.len());
    assert!(keys.contains("external-observation:manage"));
    assert!(keys.contains("application:manage-ownership"));
    assert!(keys.contains("identity:attest"));
    assert!(keys.contains("external-association:manage"));
    assert!(keys.contains("wallet:view"));
    assert!(keys.contains("issuance:revoke"));
    assert!(keys.contains("verification:execute"));
    assert!(keys.contains("audit:ingest"));
    assert!(keys.contains("passport-certificate:issue"));
    assert!(keys.contains("passport-certificate:issue-csca"));
    assert!(keys.contains("mdoc-certificate:issue-iaca"));
    assert!(keys.contains("mdoc-certificate:issue"));
    for action in [
        "view",
        "create",
        "update",
        "suspend",
        "revoke",
        "retire",
        "rotate-key",
        "enroll",
    ] {
        assert!(keys.contains(&format!("agent-identity:{action}")));
    }
    for resource in ["machine-identity", "machine-authorization-policy"] {
        for action in ["create", "update", "view"] {
            assert!(keys.contains(&format!("{resource}:{action}")));
        }
    }
    assert!(keys.contains("machine-authentication-policy:assign"));
    assert!(keys.contains("delegation-grant:view"));
    assert!(keys.contains("delegation-grant:approve"));
    for action in ["create", "suspend", "reinstate", "revoke"] {
        assert!(keys.contains(&format!("delegation-grant:{action}")));
    }
}

#[test]
fn system_role_templates_preserve_intended_entitlements() {
    let catalog = permission_catalog().expect("shared permission catalog must parse");
    let templates = system_role_templates(&catalog);
    assert_eq!(
        templates.iter().map(|role| role.name).collect::<Vec<_>>(),
        vec![
            "owner",
            "admin",
            "access_admin",
            "catalog_admin",
            "reviewer",
            "operator",
            "viewer",
            "applicant",
        ]
    );
    assert_eq!(
        templates
            .iter()
            .filter(|role| role.is_default_for_new_members)
            .map(|role| role.name)
            .collect::<Vec<_>>(),
        vec!["applicant"]
    );
    let owner = templates
        .iter()
        .find(|role| role.name == "owner")
        .expect("owner template must exist");
    assert_eq!(owner.permission_keys.len(), catalog.len());
    for template in &templates {
        for key in [
            "machine-identity:create",
            "machine-identity:update",
            "machine-identity:suspend",
            "machine-identity:revoke",
            "machine-identity:retire",
            "machine-authentication-policy:assign",
            "machine-authorization-policy:create",
            "machine-authorization-policy:update",
            "machine-authorization-policy:activate",
            "machine-authorization-policy:archive",
        ] {
            assert_eq!(
                template.permission_keys.contains(key),
                matches!(template.name, "owner" | "admin"),
                "unexpected full machine administration permission for {}",
                template.name
            );
        }
        for key in [
            "agent-identity:enroll",
            "delegation-grant:create",
            "delegation-grant:suspend",
            "delegation-grant:reinstate",
            "delegation-grant:revoke",
        ] {
            assert_eq!(
                template.permission_keys.contains(key),
                matches!(template.name, "owner" | "admin"),
                "unexpected enrollment or delegated lifecycle permission for {}",
                template.name
            );
        }
        assert_eq!(
            template
                .permission_keys
                .contains("delegation-grant:approve"),
            matches!(template.name, "owner" | "admin"),
            "unexpected representation authority for {}",
            template.name
        );
        for action in [
            "create",
            "update",
            "suspend",
            "revoke",
            "retire",
            "rotate-key",
        ] {
            assert_eq!(
                template
                    .permission_keys
                    .contains(&format!("agent-identity:{action}")),
                matches!(template.name, "owner" | "admin" | "access_admin"),
                "unexpected agent administration permission for {}",
                template.name
            );
        }
        for key in ["identity:attest", "external-association:manage"] {
            assert_eq!(
                template.permission_keys.contains(key),
                matches!(template.name, "owner" | "admin"),
                "unexpected association authority for {}",
                template.name
            );
        }
        assert_eq!(
            template
                .permission_keys
                .contains("application:manage-ownership"),
            matches!(template.name, "owner" | "admin"),
            "unexpected ownership authority for {}",
            template.name
        );
    }
    assert!(owner
        .permission_keys
        .contains("passport-certificate:issue-csca"));
    let applicant = templates
        .iter()
        .find(|role| role.name == "applicant")
        .expect("applicant template must exist");
    assert_eq!(
        applicant.permission_keys,
        APPLICANT_PERMISSION_KEYS
            .iter()
            .map(|key| (*key).to_owned())
            .collect()
    );
    let operator = templates
        .iter()
        .find(|role| role.name == "operator")
        .expect("operator template must exist");
    assert!(operator.permission_keys.contains("issuance:revoke"));
    assert!(operator.permission_keys.contains("verification:execute"));
    assert!(operator
        .permission_keys
        .contains("passport-certificate:issue"));
    assert!(!operator
        .permission_keys
        .contains("passport-certificate:issue-csca"));
    for role in [
        "access_admin",
        "catalog_admin",
        "reviewer",
        "viewer",
        "applicant",
    ] {
        let template = templates
            .iter()
            .find(|template| template.name == role)
            .unwrap();
        assert!(!template
            .permission_keys
            .contains("passport-certificate:issue"));
    }
}
