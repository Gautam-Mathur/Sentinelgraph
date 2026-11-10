import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class ActorContext:
    user_id: uuid.UUID
    email: str
    display_name: str
    tenant_id: uuid.UUID
    tenant_slug: str
    tenant_name: str
    tenant_is_demo: bool
    role: str
    request_id: str
    auth_method: str = "local_dev"
