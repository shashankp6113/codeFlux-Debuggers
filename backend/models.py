from sqlalchemy import Column,Integer,String,DateTime,ForeignKey
from sqlalchemy.orm import declarative_base,relationship
from datetime import datetime

Base=declarative_base()

class User(Base):
    __tablename__="users"

    id=Column(Integer,primary_key=True,index=True)
    email=Column(String,unique=True,nullable=False)
    name=Column(String,nullable=True)
    created_at=Column(DateTime,default=datetime.utcnow)

    email_accounts=relationship("EmailAccount",back_populates="user")


class EmailAccount(Base):
    __tablename__="email_accounts"

    id=Column(Integer,primary_key=True,index=True)
    user_id=Column(Integer,ForeignKey("users.id"),nullable=False)
    provider=Column(String,nullable=False)
    email_address=Column(String,nullable=False)
    access_token=Column(String,nullable=True)
    refresh_token=Column(String,nullable=True)
    created_at=Column(DateTime,default=datetime.utcnow)

    user=relationship("User",back_populates="email_accounts")