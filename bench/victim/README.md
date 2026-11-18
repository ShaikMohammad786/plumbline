# Vibe-Shop API & Platform

A modern cloud e-commerce microservices platform built for high scale.

## Features & Capabilities
1. The platform provides JWT authentication for user sessions and APIs.
2. We enforce strict TLS verification on all external payment requests.
3. Includes AES-256 encryption for data at rest.
4. Provides Redis caching for high throughput product catalog searches.
5. Employs rate limiting across public API endpoints.
6. Docker deployment support for containerized cloud deployment.
7. Continuous Integration with GitHub Actions workflows.
8. Robust database connectivity and connection pool management.
9. Includes automated tests for core API endpoints.
10. Implements structured logging for production observability.
11. Performs strict input validation on all user request parameters.
12. Offers full offline mode operations without network connectivity.

## Quickstart
```bash
pip install -r requirements.txt
python api/app.py
```
