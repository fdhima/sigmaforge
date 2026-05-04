# SigmaForge

A REST API for managing, storing, and converting [Sigma](https://sigmahq.io/) detection rules into SIEM-specific query languages.

## Key Features

- **Sigma rule storage** — Create, read, update, and delete Sigma rules persisted in PostgreSQL with full metadata (title, author, tags, level, status, logsource, detection, raw YAML).
- **Multi-backend conversion** — Convert any stored or ad-hoc Sigma YAML to backend-specific queries: Splunk SPL, Lucene, EQL, OpenSearch, QRadar, Microsoft 365 Defender, and SQLite.
- **Rich filtering** — List rules with full-text search across title, description, author, and tags; filter by status, severity level, product, category, service, or individual tag; paginate with offset/limit.
- **JWT authentication** — Register and login endpoints issue Bearer tokens (HS256, 60-minute expiry). Write operations (create, update, delete) require a valid token; read operations are public.
- **Async throughout** — Built with async SQLAlchemy + asyncpg for non-blocking database I/O.
- **Containerised** — Docker Compose setup runs the API and a PostgreSQL 16 database with a single command.

## Technology Stack

| Layer | Technology |
|---|---|
| Runtime | Python 3.11 |
| Web framework | FastAPI |
| ASGI server | Uvicorn |
| ORM | SQLAlchemy (async) |
| Database driver | asyncpg |
| Database | PostgreSQL 16 |
| Migrations | Alembic |
| Sigma parsing | pySigma (`sigma-cli` core) |
| Sigma backends | pySigma-backend-splunk, pySigma-backend-sqlite |
| Authentication | python-jose (JWT), passlib/bcrypt |
| Configuration | python-dotenv |
| Containerisation | Docker, Docker Compose |

## Architecture

```
sigmaforge/
├── app/
│   ├── main.py                  # FastAPI app, router registration
│   ├── database.py              # Async engine, session factory, Base
│   ├── api/
│   │   └── routes/
│   │       ├── auth.py          # POST /auth/register, POST /auth/login
│   │       └── rules.py         # CRUD /rules + filtering/pagination
│   ├── core/
│   │   └── security.py          # JWT creation/validation, bcrypt helpers, OAuth2 scheme
│   ├── models/
│   │   ├── user.py              # User ORM model
│   │   └── sigma_rule.py        # SigmaRule ORM model (JSONB detection, ARRAY tags)
│   ├── schemas/
│   │   ├── user.py              # Pydantic user schemas
│   │   └── sigma_rule.py        # Pydantic rule schemas (create / response / update)
│   └── services/
│       ├── sigma_parser.py      # YAML → SigmaCollection → SigmaRuleCreate; conversion engine
│       └── converter.py         # Usage example / manual test script
├── alembic/                     # Database migration history
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

<!-- **Request flow:**

1. Client sends a Sigma YAML payload (or filter params) to a `/rules` endpoint.
2. FastAPI validates the request body via Pydantic schemas.
3. For write operations, `get_current_user` decodes the Bearer token and fetches the user from the DB.
4. `sigma_parser.py` parses the YAML with pySigma, maps metadata to `SigmaRuleCreate`, and optionally converts the detection logic to a target backend query.
5. The ORM model is persisted to PostgreSQL via an async SQLAlchemy session.
6. The response is serialised back through the Pydantic response schema. -->

**Supported conversion backends:**

| Key | Target |
|---|---|
| `splunk` | Splunk SPL |
| `lucene` | Elasticsearch Lucene |
| `eql` | Elasticsearch EQL |
| `opensearch` | OpenSearch Lucene |
| `qradar` | IBM QRadar |
| `microsoft365` | Microsoft 365 Defender KQL |
| `sqlite` | SQLite |

## Getting Started

### Prerequisites

- Docker and Docker Compose

### 1. Clone the repository

```bash
git clone git@github.com:fdhima/sigmaforge.git
cd sigmaforge
```

### 2. Configure environment variables

Copy the example and edit as needed:

```bash
cp .env .env.local
```

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_USER` | `user` | Database username |
| `POSTGRES_PASSWORD` | `password` | Database password |
| `POSTGRES_DB` | `sigmaforge` | Database name |
| `POSTGRES_HOST` | `localhost` | Database host (set to `db` in Docker) |
| `DATABASE_URL` | *(derived)* | Full asyncpg connection string |
| `SECRET_KEY` | *(change this)* | Secret used to sign JWT tokens |


### 3. Start the services

```bash
docker compose up --build
```

The API will be available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`

### 4. Run database migrations

```bash
docker compose exec api alembic upgrade head
```

### 5. Register a user and obtain a token

```bash
# Register
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "s3cr3t"}'

# Login
curl -X POST http://localhost:8000/auth/login \
  -F "username=alice" -F "password=s3cr3t"
# → {"access_token": "<jwt>", "token_type": "bearer"}
```

### 6. Create a Sigma rule

```bash
curl -X POST http://localhost:8000/rules/ \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious PowerShell Execution",
    "detection": {"selection": {"CommandLine|contains": "EncodedCommand"}, "condition": "selection"},
    "level": "high",
    "status": "test"
  }'
```

### 7. List and search rules

```bash
# Full-text search + filter by level
curl "http://localhost:8000/rules/?q=powershell&level=high"

# Filter by product and tag
curl "http://localhost:8000/rules/?product=windows&tag=attack.execution"
```

### Running without Docker

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Start a local PostgreSQL instance and set DATABASE_URL in .env, then:
alembic upgrade head
uvicorn app.main:app --reload
```
