//! The public example executes the same stored request and evaluator as wallets.
use super::*;
use crate::public_verification_example::{
    claim_example, example_submission, finish_example_attempt, require_example_owner,
};
use crate::{
    DemoHolder, DemoHolderError, FlowInstanceRecord, PreparedVerificationRequest,
    VerificationRequestRetrievalOptions,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExampleRequest {}

pub(super) async fn example(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(_request): Json<ExampleRequest>,
) -> Result<Response, FlowHttpError> {
    let options = configured(&state)?;
    origin(options, &headers, true)?;
    let key = capability(&headers)?;
    let instance = state
        .repository
        .instance(&id.to_string())
        .await?
        .ok_or_else(unavailable)?;
    let view = current_view(&state, options, &key, &instance, Utc::now()).await?;
    let Some(example_id) = view.example_id.as_deref() else {
        return Err(unavailable());
    };
    if !matches!(
        view.status,
        PublicVerificationSessionStatus::AwaitingWallet
            | PublicVerificationSessionStatus::Verifying
    ) {
        return Ok(Json(view).into_response());
    }
    let selection = PublicVerificationSelection {
        catalog_revision: view.catalog_revision.clone(),
        scenario_id: view.scenario_id.clone(),
        choice_id: view.choice_id.clone(),
        consent: true,
        example_id: Some(example_id.into()),
    };
    options.catalog.select(&selection).map_err(catalog_error)?;
    let specimen = options
        .catalog
        .example(&view.scenario_id, example_id)
        .map_err(catalog_error)?;
    let holder_did = options.demo_holder_did.as_deref().ok_or_else(unavailable)?;
    let Some((claimed, owner)) = claim_example(&instance, Utc::now()).map_err(session_error)?
    else {
        return Ok((StatusCode::ACCEPTED, Json(view)).into_response());
    };
    if !state
        .repository
        .compare_and_swap_instance(&claimed, instance.status, instance.updated_at)
        .await?
    {
        return latest(&state, options, &key, &instance.id, StatusCode::ACCEPTED).await;
    }
    let execution = execute(&state, claimed, owner, holder_did, specimen).await;
    // Always reconcile the stored winner. A wallet, cancellation or another
    // recovered attempt may have completed while a dependency was in flight.
    let current = state
        .repository
        .instance(&instance.id)
        .await?
        .ok_or_else(unavailable)?;
    if current.status.is_terminal() {
        return latest(&state, options, &key, &instance.id, StatusCode::OK).await;
    }
    let rejected = matches!(execution, Err(ExecutionError::InputRejected));
    if let Ok(released) = finish_example_attempt(&current, owner, rejected, Utc::now()) {
        // A lost CAS never overwrites another operation or terminal result.
        state
            .repository
            .compare_and_swap_instance(&released, current.status, current.updated_at)
            .await?;
    }
    match execution {
        Err(ExecutionError::Http(error)) => Err(error),
        _ => latest(&state, options, &key, &instance.id, StatusCode::OK).await,
    }
}

async fn latest(
    state: &FlowHttpState,
    options: &PublicVerificationOptions,
    key: &PublicVerificationSessionKey,
    id: &str,
    status: StatusCode,
) -> Result<Response, FlowHttpError> {
    let current = state
        .repository
        .instance(id)
        .await?
        .ok_or_else(unavailable)?;
    Ok((
        status,
        Json(current_view(state, options, key, &current, Utc::now()).await?),
    )
        .into_response())
}

enum ExecutionError {
    Http(FlowHttpError),
    InputRejected,
}
impl From<FlowHttpError> for ExecutionError {
    fn from(error: FlowHttpError) -> Self {
        Self::Http(error)
    }
}

async fn execute(
    state: &FlowHttpState,
    mut instance: FlowInstanceRecord,
    owner: Uuid,
    holder_did: &str,
    specimen: &crate::PublicVerificationExampleConfig,
) -> Result<(), ExecutionError> {
    // Run ordinary signed-request preparation and commit its emitted query and
    // graph progress before constructing a holder presentation.
    let expected_status = instance.status;
    let expected_updated_at = instance.updated_at;
    let ready = crate::prepare_verification_request(
        &state.providers,
        instance,
        &state.public_base_url,
        &VerificationRequestRetrievalOptions {
            request_object: state.verification.request_object.clone(),
            ..Default::default()
        },
        Utc::now().max(expected_updated_at + chrono::Duration::microseconds(1)),
    )
    .await
    .map_err(FlowHttpError::from)?;
    instance = match ready {
        PreparedVerificationRequest::Ready(ready) => ready.instance,
        PreparedVerificationRequest::Expired(expired) => expired,
    };
    if !state
        .repository
        .compare_and_swap_instance(&instance, expected_status, expected_updated_at)
        .await
        .map_err(FlowHttpError::from)?
    {
        return Err(conflict().into());
    }
    require_example_owner(&instance, owner, Utc::now()).map_err(session_error)?;
    let signer = state
        .providers
        .signing_identity
        .as_deref()
        .ok_or_else(temporarily_unavailable)?;
    let holder = DemoHolder::resolve(signer, &instance.organization_id, holder_did)
        .await
        .map_err(holder_error)?;
    let presentation = holder
        .presentation(
            &state.providers,
            &instance,
            &specimen.profile,
            &specimen.credential,
        )
        .await
        .map_err(holder_error)?;
    // Check lease/terminal ownership after KMS returns, before evaluation.
    instance = state
        .repository
        .instance(&instance.id)
        .await
        .map_err(FlowHttpError::from)?
        .ok_or_else(unavailable)?;
    require_example_owner(&instance, owner, Utc::now()).map_err(session_error)?;
    let input =
        example_submission(&instance, presentation.into_compact()).map_err(session_error)?;
    crate::http_verification::evaluate_submission(state, instance, input, false).await?;
    Ok(())
}

fn conflict() -> FlowHttpError {
    FlowHttpError::new(
        StatusCode::CONFLICT,
        "verification_example_changed",
        "Verification session changed; check its current result",
    )
}
fn temporarily_unavailable() -> FlowHttpError {
    FlowHttpError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "verification_example_unavailable",
        "The example is temporarily unavailable",
    )
}
fn holder_error(error: DemoHolderError) -> ExecutionError {
    match error {
        DemoHolderError::CredentialInvalid => ExecutionError::InputRejected,
        DemoHolderError::Definition(error) => ExecutionError::Http(error.into()),
        DemoHolderError::Provider(error) => ExecutionError::Http(error.into()),
        _ => ExecutionError::Http(temporarily_unavailable()),
    }
}
