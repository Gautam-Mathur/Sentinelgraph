from fastapi import APIRouter

from app.api.v1.analysis import (
    assessments_router,
    imports_router,
    paths_router,
    remediations_router,
    reports_router,
)
from app.api.v1.auth import auth_router, health_router
from app.api.v1.governance import (
    audit_router,
    integrations_router,
    jobs_router,
    retention_router,
    webhooks_router,
)
from app.api.v1.inventory import (
    assets_router,
    findings_router,
    identities_router,
    relationships_router,
)
from app.api.v1.tenants import dashboard_router, tenants_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(tenants_router)
api_v1_router.include_router(dashboard_router)
api_v1_router.include_router(assets_router)
api_v1_router.include_router(identities_router)
api_v1_router.include_router(findings_router)
api_v1_router.include_router(relationships_router)
api_v1_router.include_router(imports_router)
api_v1_router.include_router(assessments_router)
api_v1_router.include_router(paths_router)
api_v1_router.include_router(remediations_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(integrations_router)
api_v1_router.include_router(audit_router)
api_v1_router.include_router(jobs_router)
api_v1_router.include_router(retention_router)
api_v1_router.include_router(webhooks_router)
