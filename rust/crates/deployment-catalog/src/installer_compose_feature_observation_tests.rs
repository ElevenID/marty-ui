use super::*;

fn runtime(role: &str, id: char) -> ContainerIdentity {
    ContainerIdentity {
        id: id.to_string().repeat(64),
        service: role.into(),
        image: format!("example.invalid/services@sha256:{}", "a".repeat(64)),
        config_hash: "b".repeat(64),
        setup: false,
        setup_execution: None,
        health_required: true,
        cap_add: BTreeSet::new(),
        cap_drop: BTreeSet::from(["ALL".into()]),
        read_only: true,
        memory_limit: 268435456,
    }
}

fn prior() -> ProjectResources {
    ProjectResources {
        containers: BTreeMap::from([
            ("gateway".into(), runtime("gateway", 'c')),
            ("flow".into(), runtime("flow", 'd')),
        ]),
        networks: BTreeMap::from([("project_default".into(), "e".repeat(64))]),
        volumes: BTreeSet::from(["project_existing".into()]),
    }
}

#[test]
fn only_the_feature_added_set_admits_a_new_delegated_use_role() {
    let prior = prior();
    let selected = BTreeSet::from(["flow".into(), "delegated-use".into()]);
    let added = BTreeSet::from(["delegated-use".into()]);
    // Pre-create inspection retains the original full project census.
    assert!(replacement_observation_census(
        &prior, &prior, &selected, &added
    ));
    let mut created = prior.clone();
    created
        .containers
        .insert("flow".into(), runtime("flow", 'f'));
    created
        .containers
        .insert("delegated-use".into(), runtime("delegated-use", '1'));
    assert!(replacement_observation_census(
        &prior, &created, &selected, &added
    ));
    // Generic and producer observations pass no added-role capability.
    assert!(!replacement_observation_census(
        &prior,
        &created,
        &selected,
        &BTreeSet::new()
    ));
    assert!(!replacement_observation_census(
        &prior,
        &created,
        &BTreeSet::from(["flow".into()]),
        &added
    ));
    let mut impostor = created;
    impostor.containers.get_mut("delegated-use").unwrap().setup = true;
    assert!(!replacement_observation_census(
        &prior, &impostor, &selected, &added
    ));
}

#[test]
fn feature_addition_does_not_admit_unrelated_roles_resources_or_replacement_ids() {
    let prior = prior();
    let selected = BTreeSet::from(["delegated-use".into()]);
    let added = selected.clone();
    let mut expected = prior.clone();
    expected
        .containers
        .insert("delegated-use".into(), runtime("delegated-use", '1'));
    for case in ["role", "network", "volume", "neighbor", "missing-neighbor"] {
        let mut changed = expected.clone();
        match case {
            "role" => {
                changed
                    .containers
                    .insert("unselected".into(), runtime("unselected", '2'));
            }
            "network" => {
                changed
                    .networks
                    .insert("project_other".into(), "3".repeat(64));
            }
            "volume" => {
                changed.volumes.insert("project_other".into());
            }
            "neighbor" => {
                changed.containers.get_mut("gateway").unwrap().id = "4".repeat(64);
            }
            _ => {
                changed.containers.remove("flow");
            }
        }
        assert!(
            !replacement_observation_census(&prior, &changed, &selected, &added),
            "{case}"
        );
    }
    assert!(!replacement_observation_census(
        &prior,
        &expected,
        &selected,
        &BTreeSet::from(["unselected".into()])
    ));
    // An existing role cannot be recategorized as the new-role capability.
    assert!(!replacement_observation_census(
        &expected, &expected, &selected, &added
    ));
}
