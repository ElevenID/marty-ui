// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only activation qualification. Installation and grants belong to the owner.
use axum::Router;
use sqlx::PgPool;
use std::time::Duration;

pub async fn prepare_router(
    pool: &PgPool,
    enabled: bool,
    service_key: Option<&str>,
) -> Result<Option<Router>, &'static str> {
    if !enabled {
        return Ok(None);
    }
    let key = service_key.ok_or("Association Gateway service credential is required")?;
    verify_storage(pool).await?;
    Ok(Some(crate::external_association_http::association_router(
        pool.clone(),
        key.as_bytes(),
    )?))
}

pub async fn prepare_isolated_router(
    canonical_pool: &PgPool,
    database_url: Option<&str>,
    enabled: bool,
    service_key: Option<&str>,
) -> Result<Option<Router>, &'static str> {
    const FAILURE: &str = "Isolated association storage preflight failed";
    if !enabled {
        return Ok(None);
    }
    let key = service_key.ok_or("Association Gateway service credential is required")?;
    if !(32..=512).contains(&key.len()) || !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("Invalid association Gateway service credential");
    }
    let url = database_url
        .filter(|v| !v.trim().is_empty())
        .ok_or("Separate Core association database credentials are required")?;
    let pool = tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .connect(url),
    )
    .await
    .map_err(|_| FAILURE)?
    .map_err(|_| FAILURE)?;
    let result=async {
        type Identity=(String,String,Option<String>,Option<i32>);
        const IDENTITY:&str="SELECT current_user::text,pg_catalog.current_database()::text,pg_catalog.inet_server_addr()::text,pg_catalog.inet_server_port()::int";
        let canonical:Identity=sqlx::query_as(IDENTITY).fetch_one(canonical_pool).await.map_err(|_|FAILURE)?;
        let restricted:Identity=sqlx::query_as(IDENTITY).fetch_one(&pool).await.map_err(|_|FAILURE)?;
        if canonical.0==restricted.0 || canonical.1!=restricted.1 || canonical.2.is_none() || canonical.2!=restricted.2
            || canonical.3.is_none() || canonical.3!=restricted.3 { return Err(FAILURE); }
        prepare_router(&pool,true,Some(key)).await
    }.await;
    if result.is_err() {
        pool.close().await;
    }
    result
}

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
