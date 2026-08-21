use std::sync::Arc;

use marty_organization::{OrganizationCache, OrganizationCacheKeys};
use mmf_data::{CacheConfig, CacheStore, MemoryCache};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    legacy_compatibility: Compatibility,
}

#[derive(Deserialize)]
struct Compatibility {
    user_id: String,
    organization_id: Uuid,
    membership_namespace: String,
    membership_key: String,
    permissions_namespace: String,
    permissions_key: String,
    plan_namespace: String,
    plan_key: String,
    default_plan: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-cache-behavior.json"
    )))
    .expect("organization cache fixture must be valid JSON")
}

#[test]
fn physical_cache_keys_preserve_the_legacy_consumer_contract() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    let case = fixture.legacy_compatibility;
    let logical_member_key = OrganizationCacheKeys::member(&case.user_id, case.organization_id)
        .expect("member cache key");

    assert_eq!(
        OrganizationCacheKeys::membership_namespace(),
        case.membership_namespace
    );
    assert_eq!(
        CacheConfig {
            namespace: case.membership_namespace,
            ..CacheConfig::default()
        }
        .key(&logical_member_key),
        case.membership_key
    );
    assert_eq!(
        OrganizationCacheKeys::permissions_namespace(),
        case.permissions_namespace
    );
    assert_eq!(
        CacheConfig {
            namespace: case.permissions_namespace,
            ..CacheConfig::default()
        }
        .key(&logical_member_key),
        case.permissions_key
    );
    assert_eq!(OrganizationCacheKeys::plan_namespace(), case.plan_namespace);
    assert_eq!(
        CacheConfig {
            namespace: case.plan_namespace,
            ..CacheConfig::default()
        }
        .key(&OrganizationCacheKeys::plan(case.organization_id)),
        case.plan_key
    );
}

#[tokio::test]
async fn cache_invalidation_and_plan_sync_are_behavioral_and_fail_closed() {
    let fixture = fixture().legacy_compatibility;
    let memberships = Arc::new(MemoryCache::default());
    let permissions = Arc::new(MemoryCache::default());
    let plans = Arc::new(MemoryCache::default());
    let cache = OrganizationCache::new(memberships.clone(), permissions.clone(), plans.clone());
    let member_key = OrganizationCacheKeys::member(&fixture.user_id, fixture.organization_id)
        .expect("member key");
    memberships
        .set(&member_key, b"membership".to_vec(), None, 0)
        .await
        .expect("seed membership");
    permissions
        .set(&member_key, b"permissions".to_vec(), None, 0)
        .await
        .expect("seed permissions");

    cache
        .invalidate_member(&fixture.user_id, fixture.organization_id)
        .await
        .expect("invalidate both member cache families");
    assert!(!memberships
        .exists(&member_key, 0)
        .await
        .expect("membership"));
    assert!(!permissions
        .exists(&member_key, 0)
        .await
        .expect("permissions"));

    cache
        .store_plan(fixture.organization_id, &fixture.default_plan, 0)
        .await
        .expect("store default plan");
    assert_eq!(
        cache
            .load_plan(fixture.organization_id, 0)
            .await
            .expect("load plan")
            .as_deref(),
        Some(fixture.default_plan.as_str())
    );
    assert!(cache
        .invalidate_member(" ", fixture.organization_id)
        .await
        .is_err());
    assert!(cache
        .store_plan(fixture.organization_id, "", 0)
        .await
        .is_err());
}
