from sqlalchemy import Column,Integer,String,Text,DateTime,ForeignKey,JSON,UniqueConstraint
from sqlalchemy.orm import declarative_base,relationship
from datetime import datetime

Base=declarative_base()

class User(Base):
    __tablename__="users"

    id=Column(Integer,primary_key=True,index=True)
    email=Column(String,unique=True,nullable=False)
    name=Column(String,nullable=True)
    created_at=Column(DateTime,default=datetime.utcnow)

    email_accounts=relationship("EmailAccount",back_populates="user", cascade="all, delete-orphan")


class EmailAccount(Base):
    __tablename__="email_accounts"

    id=Column(Integer,primary_key=True,index=True)
    user_id=Column(Integer,ForeignKey("users.id"),nullable=False,index=True)
    provider=Column(String,nullable=False)
    email_address=Column(String,nullable=False)
    access_token=Column(String,nullable=True)
    refresh_token=Column(String,nullable=True)
    created_at=Column(DateTime,default=datetime.utcnow)

    user=relationship("User",back_populates="email_accounts")
    sync_state = relationship("EmailAccountSyncState", back_populates="account", uselist=False, cascade="all, delete-orphan")
    emails=relationship("Email",back_populates="email_account", cascade="all, delete-orphan")


class Email(Base):
    __tablename__="emails"
    
    __table_args__ = (
        UniqueConstraint('email_account_id', 'message_id', name='uq_email_account_message'),
    )

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
    received_at=Column(DateTime,nullable=True,index=True)
    created_at=Column(DateTime,default=datetime.utcnow)

    email_account=relationship("EmailAccount",back_populates="emails")
    forensic_analysis=relationship(
        "ForensicAnalysis",back_populates="email",uselist=False, cascade="all, delete-orphan"
    )


class ForensicAnalysis(Base):
    """Stores the result of deterministic header forensic analysis for an email.

    One-to-one with Email. The `analysis` column holds the complete structured
    forensic result as JSON (JSONB on PostgreSQL).
    """
    __tablename__="forensic_analyses"

    id=Column(Integer,primary_key=True,index=True)
    email_id=Column(Integer,ForeignKey("emails.id"),nullable=False,unique=True)
    analysis=Column(JSON,nullable=False)
    created_at=Column(DateTime,default=datetime.utcnow)

    email=relationship("Email",back_populates="forensic_analysis")
class EmailAccountSyncState(Base):
    __tablename__ = "email_account_sync_states"

    email_account_id = Column(Integer, ForeignKey("email_accounts.id", ondelete="CASCADE"), primary_key=True)
    status = Column(String, default="idle", nullable=False)
    total_discovered = Column(Integer, default=0, nullable=False)
    processed = Column(Integer, default=0, nullable=False)
    newly_added = Column(Integer, default=0, nullable=False)
    skipped_duplicate = Column(Integer, default=0, nullable=False)
    failed_count = Column(Integer, default=0, nullable=False)
    errors = Column(JSON, default=list, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    account = relationship("EmailAccount", back_populates="sync_state")
