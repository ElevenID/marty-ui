"""
Organization Service

Organization management microservice.
Handles organizations, members, and API keys.

Ports:
- HTTP API on port 8002
- RabbitMQ events

Architecture:
- domain/: Organization, Member, ApiKey entities
- application/: Organization CRUD, Member management, API key operations
- infrastructure/: FastAPI, PostgreSQL, RabbitMQ adapters
"""
