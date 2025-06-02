import enum
from typing import Optional
from pydantic import BaseModel, EmailStr

class UserStatus(enum.Enum):
    pending_activation = "pending_activation"
    active = "active"
    disabled = "disabled"

class ActiveDirectoryUser(BaseModel):
    id: int
    username: str
    email:EmailStr
    encrypted_hash:str 
    es_roles: Optional[str] = 'ad_sync'
    status: str # type: ignore

    class Config:
        from_attributes = True