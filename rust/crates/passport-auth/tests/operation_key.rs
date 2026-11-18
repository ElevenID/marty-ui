use marty_passport_auth::valid_operation_idempotency_key;

#[test]
fn operation_keys_have_no_cache_trim_or_duplicate_value_aliases() {
    assert!(valid_operation_idempotency_key("owned.cancel-1:request_2"));
    for value in [
        "",
        " owned-1",
        "owned-1 ",
        "owned-1,owned-2",
        "a/b",
        "é",
        "a\n",
    ] {
        assert!(!valid_operation_idempotency_key(value), "{value:?}");
    }
    assert!(valid_operation_idempotency_key(&"a".repeat(128)));
    assert!(!valid_operation_idempotency_key(&"a".repeat(129)));
}
