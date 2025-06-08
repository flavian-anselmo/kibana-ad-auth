import enum
from typing import Optional
from pydantic import BaseModel, EmailStr

class UserStatus(enum.Enum):
    pending_activation = "pending_activation"
    active = "active"
    disabled = "disabled"

class ActiveDirectoryUser(BaseModel):
    # id: int
    username: str
    encrypted_hash:str 

    # email:EmailStr
    # es_roles: Optional[str] = 'ad_sync'
    # status: str 

    class Config:
        from_attributes = True

class UserActivationResponse(BaseModel):
    message:str 
    class Config:
        from_attributes = True