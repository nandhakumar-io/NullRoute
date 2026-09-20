# NetSecAuditor: scan stop / delete / bulk-upload changes

Copy these files over the same paths in your project (paths are relative to the repo root).

## Backend (new)
- backend/app/services/scan_runner.py      background execution, concurrency cap, guaranteed force-stop, orphan repair
- backend/app/services/scan_deletion.py    metadata-driven delete of a scan and its dependents
- backend/alembic/versions/y0z1a2b3c4d5_add_scan_source_filename.py
- backend/tests/test_scan_lifecycle.py     23 tests

## Backend (modified)
- backend/app/routers/scans.py    DELETE /{id}, POST /bulk-delete, POST /bulk-stop, robust stop/pause/resume, bulk-upload rewrite
- backend/app/services/pipeline.py
- backend/app/main.py             startup reconcile + shutdown hook
- backend/app/models/db.py, schemas.py, db.py    scans.source_filename

## Frontend (modified)
- frontend/src/pages/Validation.tsx
- frontend/src/pages/ScanDetail.tsx
- frontend/src/components/RunningPipelines.tsx
- frontend/src/lib/toast.tsx
- frontend/src/index.css
- frontend/src/api.ts

## Env knobs
SCAN_PIPELINE_CONCURRENCY (3), SCAN_STOP_GRACE_SECONDS (3), SCAN_BULK_MAX_FILES (50),
SCAN_BULK_MAX_TOTAL_BYTES (52428800), SCAN_RECONCILE_ON_STARTUP (true)

## Not yet verified
Full backend suite: 384 passed, 22 failed, 1 error. Not yet compared against the original code,
so it is unknown which failures pre-date these changes. No browser test of the UI.
