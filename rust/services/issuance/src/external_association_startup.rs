// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only activation qualification. Installation and grants belong to the owner.
use sqlx::PgPool;

pub async fn verify_storage(pool: &PgPool) -> Result<(), &'static str> {
    const FAILURE: &str = "External association storage preflight failed";
    let mut tx = pool.begin().await.map_err(|_| FAILURE)?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|_| FAILURE)?;
    sqlx::query("SET LOCAL statement_timeout='5s'")
        .execute(&mut *tx)
        .await
        .map_err(|_| FAILURE)?;
    crate::external_association_schema::validate(&mut tx)
        .await
        .map_err(|_| FAILURE)?;
    let safe: bool = sqlx::query_scalar(include_str!(
        "../schema/external_association_role_query.sql"
    ))
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| FAILURE)?;
    tx.rollback().await.map_err(|_| FAILURE)?;
    if !safe {
        return Err(FAILURE);
    }
    Ok(())
}
