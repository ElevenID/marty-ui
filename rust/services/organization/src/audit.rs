use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, Utc};
use uuid::Uuid;

use crate::application::{OrganizationApplication, OrganizationApplicationError};
use crate::domain::{AuditEvent, AuditEventQuery};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditQueryInput {
    pub organization_id: Uuid,
    pub page: i64,
    pub per_page: i64,
    pub legacy_limit: Option<i64>,
    pub legacy_offset: i64,
    pub category: Option<String>,
    pub event_type: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub action: Option<String>,
    pub actor: Option<String>,
    pub severity: Option<String>,
    pub search: Option<String>,
    pub ip_address: Option<String>,
    pub time_range: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedAuditQuery {
    pub organization_id: Uuid,
    pub page: u32,
    pub per_page: u32,
    pub query: AuditEventQuery,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuditEventPage {
    pub events: Vec<AuditEvent>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

impl OrganizationApplication {
    pub async fn get_audit_event(
        &self,
        organization_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<AuditEvent>, OrganizationApplicationError> {
        Ok(self
            .store
            .audit_event_by_id(organization_id, event_id)
            .await?)
    }

    pub async fn query_audit_events(
        &self,
        input: AuditQueryInput,
        now: DateTime<Utc>,
    ) -> Result<AuditEventPage, OrganizationApplicationError> {
        let normalized = normalize_audit_query(input, now)?;
        let total = self
            .store
            .count_audit_events(normalized.organization_id, &normalized.query)
            .await?;
        let events = self
            .store
            .list_audit_events(normalized.organization_id, &normalized.query)
            .await?;
        Ok(AuditEventPage {
            events,
            total,
            page: normalized.page,
            per_page: normalized.per_page,
        })
    }
}

pub fn normalize_audit_query(
    input: AuditQueryInput,
    now: DateTime<Utc>,
) -> Result<NormalizedAuditQuery, OrganizationApplicationError> {
    let (page, per_page) = normalize_pagination(
        input.page,
        input.per_page,
        input.legacy_limit,
        input.legacy_offset,
    );
    let from = match input.start_date.as_deref() {
        Some(value) => Some(parse_datetime(
            value,
            "start_date must be an ISO 8601 datetime",
        )?),
        None => start_from_time_range(input.time_range.as_deref(), now)?,
    };
    let to = input
        .end_date
        .as_deref()
        .map(|value| parse_datetime(value, "end_date must be an ISO 8601 datetime"))
        .transpose()?;
    let offset = page.saturating_sub(1).saturating_mul(per_page);
    Ok(NormalizedAuditQuery {
        organization_id: input.organization_id,
        page,
        per_page,
        query: AuditEventQuery {
            category: input.category,
            event_type: input.event_type,
            resource_type: input.resource_type,
            resource_id: input.resource_id,
            action: input.action,
            actor_id: input.actor,
            severity: input.severity,
            search: input.search,
            ip_address: input.ip_address,
            from,
            to,
            limit: per_page,
            offset,
        },
    })
}

#[must_use]
pub fn normalize_pagination(
    mut page: i64,
    mut per_page: i64,
    legacy_limit: Option<i64>,
    legacy_offset: i64,
) -> (u32, u32) {
    if let Some(limit) = legacy_limit {
        per_page = limit;
        page = if limit > 0 {
            legacy_offset.div_euclid(limit).saturating_add(1)
        } else {
            1
        };
    }
    let page = u32::try_from(page.max(1)).unwrap_or(u32::MAX);
    let per_page = u32::try_from(per_page.clamp(1, 1_000)).unwrap_or(1_000);
    (page, per_page)
}

pub fn start_from_time_range(
    time_range: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, OrganizationApplicationError> {
    let Some(value) = time_range else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(None);
    }
    if matches!(normalized.as_str(), "all" | "all_time" | "all-time") {
        return Ok(None);
    }
    let (amount, unit) = normalized.split_at(normalized.len().saturating_sub(1));
    if !matches!(unit, "h" | "d" | "w") {
        return Err(OrganizationApplicationError::InvalidAuditFilter(
            "time_range must use h, d, or w units",
        ));
    }
    let amount = amount.parse::<i64>().map_err(|_| {
        OrganizationApplicationError::InvalidAuditFilter(
            "time_range must start with a positive integer",
        )
    })?;
    if amount <= 0 {
        return Err(OrganizationApplicationError::InvalidAuditFilter(
            "time_range must be positive",
        ));
    }
    let duration = match unit {
        "h" => Duration::try_hours(amount),
        "d" => Duration::try_days(amount),
        "w" => Duration::try_weeks(amount),
        _ => unreachable!("unit was validated above"),
    }
    .ok_or(OrganizationApplicationError::InvalidAuditFilter(
        "time_range is out of range",
    ))?;
    now.checked_sub_signed(duration).map(Some).ok_or(
        OrganizationApplicationError::InvalidAuditFilter("time_range is out of range"),
    )
}

fn parse_datetime(
    value: &str,
    error: &'static str,
) -> Result<DateTime<Utc>, OrganizationApplicationError> {
    if let Ok(value) = DateTime::parse_from_rfc3339(value) {
        return Ok(value.with_timezone(&Utc));
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(value) = NaiveDateTime::parse_from_str(value, format) {
            return Ok(value.and_utc());
        }
    }
    if let Ok(value) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        return value
            .and_hms_opt(0, 0, 0)
            .map(|value| value.and_utc())
            .ok_or(OrganizationApplicationError::InvalidAuditFilter(error));
    }
    Err(OrganizationApplicationError::InvalidAuditFilter(error))
}
