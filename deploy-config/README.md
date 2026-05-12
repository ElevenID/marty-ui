# Deployment Config Layout

This directory separates deployment concerns by target environment to reduce accidental cross-domain or cross-stack configuration drift.

## Structure

- env/selfhost-production
- env/tunnel-beta
- compose/selfhost-production
- compose/tunnel-beta

## Rules

- selfhost-production uses elevenidllc.com values.
- tunnel-beta uses beta.elevenidllc.com values.
- Do not reuse one env file across both targets.
- Keep secrets in external secret directories, not in this repo.

## Canonical Runtime Files

- Beta tunnel runtime env: .env.tunnel.beta.local
- Beta tunnel make targets: beta-up, beta-public-ui, beta-tunnel-start, beta-check
- Selfhost production runtime env: .env.selfhost.production.local
- Selfhost production make targets: selfhost-prod-up, selfhost-prod-check, selfhost-prod-logs
- Selfhost production compose: docker-compose.selfhost.prod.yml
- Tunnel overlay compose: docker-compose.profile.tunnel.yml

Use the templates in this directory as documentation and copy sources for new operators.
