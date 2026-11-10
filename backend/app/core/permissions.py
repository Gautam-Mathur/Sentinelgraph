from enum import StrEnum

from app.core.errors import AuthorizationError


class RoleName(StrEnum):
    TENANT_ADMIN = "tenant_admin"
    ASSESSOR = "assessor"
    ANALYST = "analyst"
    REMEDIATION_OWNER = "remediation_owner"
    AUDITOR = "auditor"
    READ_ONLY = "read_only"


class Permission(StrEnum):
    TENANT_MANAGE = "tenant:manage"
    MEMBERSHIP_MANAGE = "membership:manage"
    ASSESSMENT_CREATE = "assessment:create"
    ASSESSMENT_APPROVE_SCOPE = "assessment:approve_scope"
    ASSESSMENT_READ = "assessment:read"
    IMPORT_UPLOAD = "import:upload"
    IMPORT_APPROVE = "import:approve"
    IMPORT_COMMIT = "import:commit"
    IMPORT_READ = "import:read"
    ASSET_READ = "asset:read"
    ASSET_WRITE = "asset:write"
    IDENTITY_READ = "identity:read"
    IDENTITY_WRITE = "identity:write"
    RELATIONSHIP_READ = "relationship:read"
    RELATIONSHIP_WRITE = "relationship:write"
    EVIDENCE_CHALLENGE = "evidence:challenge"
    GRAPH_BUILD = "graph:build"
    PATH_GENERATE = "path:generate"
    PATH_READ = "path:read"
    REMEDIATION_SIMULATE = "remediation:simulate"
    REMEDIATION_READ = "remediation:read"
    REPORT_GENERATE = "report:generate"
    REPORT_READ = "report:read"
    INTEGRATION_MANAGE = "integration:manage"
    INTEGRATION_READ = "integration:read"
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"
    RETENTION_MANAGE = "retention:manage"
    JOB_READ = "job:read"
    JOB_CANCEL = "job:cancel"


ROLE_PERMISSIONS: dict[RoleName, frozenset[Permission]] = {
    RoleName.TENANT_ADMIN: frozenset(Permission),
    RoleName.ASSESSOR: frozenset(
        {
            Permission.ASSESSMENT_CREATE,
            Permission.ASSESSMENT_APPROVE_SCOPE,
            Permission.ASSESSMENT_READ,
            Permission.IMPORT_UPLOAD,
            Permission.IMPORT_APPROVE,
            Permission.IMPORT_COMMIT,
            Permission.IMPORT_READ,
            Permission.ASSET_READ,
            Permission.ASSET_WRITE,
            Permission.IDENTITY_READ,
            Permission.IDENTITY_WRITE,
            Permission.RELATIONSHIP_READ,
            Permission.RELATIONSHIP_WRITE,
            Permission.EVIDENCE_CHALLENGE,
            Permission.GRAPH_BUILD,
            Permission.PATH_GENERATE,
            Permission.PATH_READ,
            Permission.REMEDIATION_SIMULATE,
            Permission.REMEDIATION_READ,
            Permission.REPORT_GENERATE,
            Permission.REPORT_READ,
            Permission.INTEGRATION_READ,
            Permission.JOB_READ,
            Permission.JOB_CANCEL,
        }
    ),
    RoleName.ANALYST: frozenset(
        {
            Permission.ASSESSMENT_READ,
            Permission.IMPORT_UPLOAD,
            Permission.IMPORT_READ,
            Permission.ASSET_READ,
            Permission.ASSET_WRITE,
            Permission.IDENTITY_READ,
            Permission.RELATIONSHIP_READ,
            Permission.RELATIONSHIP_WRITE,
            Permission.EVIDENCE_CHALLENGE,
            Permission.GRAPH_BUILD,
            Permission.PATH_GENERATE,
            Permission.PATH_READ,
            Permission.REMEDIATION_SIMULATE,
            Permission.REMEDIATION_READ,
            Permission.REPORT_GENERATE,
            Permission.REPORT_READ,
            Permission.INTEGRATION_READ,
            Permission.JOB_READ,
        }
    ),
    RoleName.REMEDIATION_OWNER: frozenset(
        {
            Permission.ASSESSMENT_READ,
            Permission.ASSET_READ,
            Permission.IDENTITY_READ,
            Permission.RELATIONSHIP_READ,
            Permission.PATH_READ,
            Permission.REMEDIATION_SIMULATE,
            Permission.REMEDIATION_READ,
            Permission.REPORT_READ,
            Permission.JOB_READ,
        }
    ),
    RoleName.AUDITOR: frozenset(
        {
            Permission.ASSESSMENT_READ,
            Permission.IMPORT_READ,
            Permission.ASSET_READ,
            Permission.IDENTITY_READ,
            Permission.RELATIONSHIP_READ,
            Permission.PATH_READ,
            Permission.REMEDIATION_READ,
            Permission.REPORT_READ,
            Permission.INTEGRATION_READ,
            Permission.AUDIT_READ,
            Permission.AUDIT_EXPORT,
            Permission.JOB_READ,
        }
    ),
    RoleName.READ_ONLY: frozenset(
        {
            Permission.ASSESSMENT_READ,
            Permission.IMPORT_READ,
            Permission.ASSET_READ,
            Permission.IDENTITY_READ,
            Permission.RELATIONSHIP_READ,
            Permission.PATH_READ,
            Permission.REMEDIATION_READ,
            Permission.REPORT_READ,
            Permission.INTEGRATION_READ,
            Permission.JOB_READ,
        }
    ),
}


def has_permission(role: str, permission: Permission) -> bool:
    try:
        role_enum = RoleName(role)
    except ValueError:
        return False
    return permission in ROLE_PERMISSIONS[role_enum]


def require_permission(role: str, permission: Permission) -> None:
    if not has_permission(role, permission):
        raise AuthorizationError(
            message=f"Role '{role}' lacks required permission '{permission.value}'.",
            code="PERMISSION_DENIED",
        )
