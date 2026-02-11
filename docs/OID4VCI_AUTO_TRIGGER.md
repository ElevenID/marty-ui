# OID4VCI Auto-Trigger Workflow

## Overview
Automatic credential offer generation when applications are approved.

## Components

### 1. Event Publisher (`services/common/events.py`)
- Lightweight HTTP-based event bus
- Publishes domain events to registered webhooks
- Supports multiple event types (application.approved, identity.verified, etc.)

### 2. Applicant Service (`services/applicant/main.py`)
- Emits `APPLICATION_APPROVED` event when applicant is approved
- Event includes applicant details (ID, email, name, vetting level)
- Non-blocking: approval succeeds even if event publishing fails

### 3. Flow Service Webhook (`services/flow/main.py`)
- Receives `APPLICATION_APPROVED` events at `/v1/flows/webhooks/application-approved`
- Finds all active OID4VCI flows with `application_approved` precondition
- Automatically starts flow instances for each matching flow
- Creates QR codes/credential offers immediately

## Workflow

```
1. Admin approves applicant
   └─> POST /v1/applicants/{id}/review { decision: "approve" }

2. Applicant service updates status
   └─> applicant.status = APPROVED

3. Event published
   └─> POST http://flow-service:8011/v1/flows/webhooks/application-approved
       {
         "event_type": "application.approved",
         "aggregate_id": "applicant-123",
         "organization_id": "org-456",
         "data": {
           "applicant_id": "applicant-123",
           "email": "user@example.com",
           "given_name": "Jane",
           "family_name": "Doe",
           "status": "approved"
         }
       }

4. Flow service receives webhook
   └─> Queries for active OID4VCI flows with precondition "application_approved"

5. For each matching flow:
   a. Creates FlowInstance with initial context:
      - application_status: "approved"
      - applicant_id, email, name
   
   b. Starts flow at first step (usually "Check Preconditions")
   
   c. Creates OID4VCI artifact:
      - Generates pre-authorized code
      - Builds credential_offer_uri
      - Creates QR code payload
   
   d. Flow is now waiting for wallet to scan QR

6. Applicant scans QR code with wallet
   └─> Wallet exchanges pre-auth code for credential
```

## Configuration

### Environment Variables

**Applicant Service**:
```bash
FLOW_SERVICE_URL=http://flow-service:8011
```

**Flow Service**:
- No additional config needed (webhook endpoint auto-registered)

### Flow Definition Setup

When creating an OID4VCI flow, configure preconditions:

```javascript
{
  "name": "Auto-Issue Employee Badge",
  "flow_type": "issuance_oid4vci",
  "preconditions": ["application_approved"],  // ← Key setting
  "steps": [...],
  "is_active": true
}
```

Available preconditions:
- `application_approved` - Auto-trigger on approval
- `identity_verified` - Require biometric verification
- `manual_admin_approval` - Wait for admin action
- `external_verification` - Wait for webhook callback

## Testing

### Manual Test

1. Create OID4VCI flow with `application_approved` precondition:
```bash
POST /v1/flows/definitions
{
  "organization_id": "org-123",
  "name": "Test Auto-Issue",
  "flow_type": "issuance_oid4vci",
  "preconditions": ["application_approved"],
  "steps": [...],
  "is_active": true
}
```

2. Create and approve applicant:
```bash
# Create applicant
POST /v1/applicants
{
  "organization_id": "org-123",
  "email": "test@example.com",
  "given_name": "Test",
  "family_name": "User"
}

# Approve applicant (triggers auto-flow)
POST /v1/applicants/{id}/review
{
  "decision": "approve",
  "notes": "All documents verified"
}
```

3. Check that flow instance was created:
```bash
GET /v1/flows/instances?organization_id=org-123
```

Should return a flow instance with:
- `subject_id` = applicant ID
- `external_reference` = "auto-approved-{applicant_id}"
- `context.triggered_by_event` = "application.approved"
- QR code artifact created

## Monitoring

### Logs

**Applicant Service**:
```
INFO: Published APPLICATION_APPROVED event for applicant {id}
```

**Flow Service**:
```
INFO: Received APPLICATION_APPROVED event for applicant {id} in org {org_id}
INFO: Auto-triggered flow {flow_id} ({name}) for applicant {id}: instance {instance_id}
INFO: Created OID4VCI artifact: {artifact_id}
```

### Metrics

Track:
- Event publish success/failure rate
- Webhook delivery latency
- Auto-triggered flow count
- QR code generation success rate

## Error Handling

### Event Publishing Fails
- Applicant approval still succeeds (logged warning)
- Admin can manually trigger flow from UI

### Webhook Delivery Fails
- Event publisher logs error
- No automatic retry (future enhancement)
- Admin can manually trigger flow

### No Matching Flows
- Webhook succeeds with `flows_triggered: 0`
- Normal scenario if org hasn't configured OID4VCI flows

### Flow Instance Creation Fails
- Logged as error
- Does not block other flows from triggering
- Returns partial success response

## Future Enhancements

1. **Retry Logic**: Add exponential backoff for failed event deliveries
2. **Dead Letter Queue**: Store failed events for manual replay
3. **Event Store**: Persist all events for audit trail
4. **Multiple Preconditions**: Support complex AND/OR logic
5. **Rate Limiting**: Prevent event flooding
6. **Message Broker**: Replace HTTP with RabbitMQ/Kafka for production
