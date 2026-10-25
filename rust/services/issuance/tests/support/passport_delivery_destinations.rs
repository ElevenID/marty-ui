//! Real catalog schema for disposable passport SQL/HTTP contracts.
pub async fn seed(pool: &sqlx::PgPool) {
    sqlx::raw_sql(include_str!(
        "../../../credential-template/migrations/0001_credential_template_schema.sql"
    ))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO credential_template_service.delivery_destinations
         (id, organization_id, name, provider, mode, setup_actor, delivery_target,
          credential_format, issuance_protocol, is_enabled, created_at, updated_at)
         SELECT id, 'org-a', id, 'physical_document_bureau', 'physical_document',
                'system', 'physical_document', 'ICAO_EMRTD', 'PHYSICAL_DOCUMENT',
                true, clock_timestamp(), clock_timestamp()
         FROM unnest($1::text[]) AS id
         ON CONFLICT (id) DO UPDATE SET organization_id='org-a', is_system=false,
             provider='physical_document_bureau', mode='physical_document',
             delivery_target='physical_document', credential_format='ICAO_EMRTD',
             issuance_protocol='PHYSICAL_DOCUMENT', connector_id=NULL, is_enabled=true",
    )
    .bind(&["destination-http", "destination-poll-race", "destination"])
    .execute(pool)
    .await
    .unwrap();
}
