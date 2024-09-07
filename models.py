from typing import List

from sqlalchemy import Column, String, Integer, ForeignKey
from sqlalchemy.orm import relationship, Mapped

from database import Base


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(59), unique=True)
    hashed_password = Column(String(1024))
    requests: Mapped[List["UserRequests"]] = relationship(backref="user")


class UserRequests(Base):
    __tablename__ = "requests"
    
    id = Column(Integer, primary_key=True, index=True)
    text = Column(String(256), unique=False)
    request = Column(String(20), unique=False)
    user_id = Column(Integer, ForeignKey("users.id"))