from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr


class UserInfoFromIDProvider(BaseModel):
    email: EmailStr


class OIDCUserCreate(BaseModel):
    email: EmailStr


class OIDCUserRead(BaseModel):
    id: UUID
    email: EmailStr
    created_at: datetime
