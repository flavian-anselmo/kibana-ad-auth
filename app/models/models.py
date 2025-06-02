from sqlalchemy import (
    Column, Integer, String, Text, Enum, DateTime, Index
)
from app.database.database import Base
from app.schema import schema
from datetime import datetime, timezone

class User(Base):
    __tablename__ = "enterprise_ad_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    es_roles = Column(Text, nullable=False)
    encrypted_hash = Column(String(255), nullable=False, default='TempPassword123!')
    status = Column(Enum(schema.UserStatus), default=schema.UserStatus.pending_activation)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc), onupdate=lambda: datetime.now(tz=timezone.utc))

    __table_args__ = (
        Index("idx_username", "username"),
        Index("idx_status", "status"),
    )
