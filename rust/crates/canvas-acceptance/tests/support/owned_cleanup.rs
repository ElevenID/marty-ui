pub(super) fn retain_failure(
    result: Result<(), String>,
    verification: Result<(), String>,
) -> Result<(), String> {
    match (result, verification) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(primary), Err(secondary)) => Err(format!("{primary}; additionally: {secondary}")),
    }
}
