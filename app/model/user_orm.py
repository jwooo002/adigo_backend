from sqlalchemy import Integer, String, DateTime
from sqlalchemy.sql.schema import Column
from app.database import Base
from pydantic import BaseModel

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(128), nullable=False)

    class Config:
        orm_mode = True
