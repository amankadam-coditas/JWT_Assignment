from src.myauth.database import Base
from sqlalchemy import Column, String, Integer

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index= True)
    hashed_password = Column(String, nullable=False, index=True)
    email = Column(String, nullable=False, index=True)