# backend — FastAPI control / monitoring API

```bash
cd project/backend
pip install -r api/requirements.txt
cp .env.example .env   # edit credentials + paths
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

OpenAPI / Swagger at http://localhost:8000/docs. SQLite at
`data/antiddos.db` (override the connection string via `DATABASE_URL`, e.g. `sqlite:///./data/antiddos.db`). Alembic
migrations under `migrations/` — apply with `alembic upgrade head`.

**Hardening (`APP_ENV=production` mode):** set `APP_ENV=production` and `CORS_ORIGINS`
(comma-separated allowlist) before starting uvicorn. The app fails
fast if `APP_ENV=production` and `CORS_ORIGINS` is unset; WebSocket
auth is enforced and rejections are logged.

## Tests

```bash
pytest tests/
```
