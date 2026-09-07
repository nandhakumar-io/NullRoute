# Files changed this session

1. backend/app/ai/model_registry.py
   - Classifier artifact path was written to HF_MINILM_MODEL (embedder's env var)
     instead of HF_DISTILBERT_MODEL. Fixed so classifier/embedder resolve
     independently on registry reload.

2. backend/app/services/model_registry_service.py
   - promote_to_production(): now calls ai_model_registry.reload_from_registry(db)
     after commit, so the newly promoted model is actually used by the next
     inference call (previously only a comment saying this "would" happen).
   - rollback(): fixed audit-log bug where old_value was captured AFTER status
     was already mutated to PRODUCTION (so old_value == new_value always).
     Now captures old_target_status and the true previous production model id
     before mutation. Also added the same reload_from_registry(db) call.

3. backend/app/services/evidence_service.py
   - Stale docstring/comment said Fabric anchoring was an "unimplemented
     extension point" when app/services/pipeline.py actually calls
     fabric_service.anchor_evidence(...) for real. Corrected comment only,
     no behavior change.

4. backend/app/routers/scans.py
   - /api/scans/upload, /api/scans/bulk-upload, /api/scans/{id}/rerun had no
     permission check (only required login, not any role/permission) even
     though require_role was imported. Any authenticated VIEWER could trigger
     scans. Fixed all three to require Permission.SCAN via require_permission.

5. backend/app/routers/ai.py
   - approve_model/reject_model used require_permission("APPROVE_AI_MAPPING")
     (raw string) instead of Permission.APPROVE_AI_MAPPING (enum value is
     lowercase "approve_ai_mapping") -- the string never matched, so these
     endpoints always 403'd.
   - promote_model/rollback_model used require_permission("ADMIN") -- "ADMIN"
     is not a member of the Permission enum at all, so these two endpoints
     ALWAYS returned 403 for every role, including SUPER_ADMIN/TENANT_ADMIN.
     Fixed to require_role("admin", "TENANT_ADMIN", "SUPER_ADMIN"), matching
     the existing admin-gating pattern already used in credentials.py:170.

6. backend/tests/test_corss_tenant_isolation_matrix.py -- DELETED
   - Misspelled, unreferenced, near-byte-identical duplicate of
     backend/tests/test_cross_tenant_isolation_matrix.py (differed only by a
     trailing newline). Confirmed nothing imports it by name before removing.

All changes verified with `python3 -m py_compile` across the full backend/app
tree after each edit. No test suite was executed (sandbox has ~2.8GB free
disk, not enough headroom to install torch/transformers from requirements.txt).
