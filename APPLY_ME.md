# NetSecAuditor: changed files only

Unzip over the repo root (paths are relative to it).

## NOT included on purpose
`backend/app/services/deployment_service.py` is corrupt in the zip you uploaded
(identical to dataset_service.py). Restore your real copy from git/backup.

## .env (edit by hand; not shipped)
AUTH_ENABLED=true
AUTH_JWT_SECRET=<openssl rand -hex 32>
BOOTSTRAP_ADMIN_PASSWORD=<first admin password, or leave blank for a one-time log password>
Also: .gitignore has `.env/*` which does not ignore the `.env` file. Rotate any live tokens.

## Notes
- Training worker image needs INSTALL_ML=true (already set in docker-compose.yml).
- No Alembic migration; new tables/columns come from app/db.py startup migrations.
- Backend tests: DATABASE_URL=sqlite:////tmp/t.db pytest tests/test_hitl_datasets_training_registry.py tests/test_local_login_and_users.py tests/test_training_examples_gate.py
