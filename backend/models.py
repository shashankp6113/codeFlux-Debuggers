from sqlalchemy import Column,Integer,String,Text,DateTime,ForeignKey
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
    emails=relationship("Email",back_populates="email_account")


class Email(Base):
    __tablename__="emails"

    id=Column(Integer,primary_key=True,index=True)
    email_account_id=Column(Integer,ForeignKey("email_accounts.id"),nullable=False)
    message_id=Column(String,nullable=True)
    subject=Column(String,nullable=True)
    sender=Column(String,nullable=False)
    recipient=Column(String,nullable=False)
    cc=Column(String,nullable=True)
    body_text=Column(Text,nullable=True)
    body_html=Column(Text,nullable=True)
    raw_headers=Column(Text,nullable=True)
    received_at=Column(DateTime,nullable=True)
    created_at=Column(DateTime,default=datetime.utcnow)

    email_account=relationship("EmailAccount",back_populates="emails")