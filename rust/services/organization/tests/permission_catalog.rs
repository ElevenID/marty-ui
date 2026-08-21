use std::collections::BTreeSet;

use marty_organization::{
    catalog::{permission_catalog, system_role_templates},
    APPLICANT_PERMISSION_KEYS,
};

#[test]
fn shared_permission_catalog_is_unique_and_complete() {
    let catalog = permission_catalog().expect("shared permission catalog must parse");
    let keys: BTreeSet<_> = catalog.iter().map(|permission| permission.key()).collect();
    assert_eq!(catalog.len(), 104);
    assert_eq!(keys.len(), catalog.len());
    assert!(keys.contains("wallet:view"));
    assert!(keys.contains("issuance:revoke"));
    assert!(keys.contains("verification:execute"));
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
}
