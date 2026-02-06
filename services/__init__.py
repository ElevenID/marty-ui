"""
Marty Microservices

This package contains the individual microservices that make up the Marty API.
Each service follows hexagonal architecture with clear separation of:
- domain/ : Pure business logic (entities, value objects, domain events)
- application/ : Use cases and port interfaces
- infrastructure/ : Adapters (HTTP, database, messaging)

Services:
- auth: Authentication and session management
- organization: Organization, members, and API key management  
- credential: Credential type configuration
- trust: Trust framework and key configuration
- issuance: OID4VCI credential issuance
- applicant: Applicant vetting and KYC
- notification: Notifications and push messaging
"""
