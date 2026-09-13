import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from models import Base, User, EmailAccount, Email

# In-memory SQLite for testing unique constraints
# SQLite supports unique constraints
TEST_ENGINE = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=TEST_ENGINE)
    yield
    Base.metadata.drop_all(bind=TEST_ENGINE)

@pytest.fixture
def db_session():
    session = TestingSessionLocal()
    yield session
    session.close()

def test_duplicate_message_id_same_account_rejected(db_session):
    u = User(email="user@test.com")
    db_session.add(u)
    db_session.commit()

    acc = EmailAccount(user_id=u.id, provider="gmail", email_address="user@test.com")
    db_session.add(acc)
    db_session.commit()

    # Insert first email
    eml1 = Email(
        email_account_id=acc.id,
        message_id="msg123",
        sender="a@b.com",
        recipient="c@d.com"
    )
    db_session.add(eml1)
    db_session.commit()

    # Insert second email with same message_id for same account
    eml2 = Email(
        email_account_id=acc.id,
        message_id="msg123",
        sender="a@b.com",
        recipient="c@d.com"
    )
    db_session.add(eml2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

def test_same_message_id_different_accounts_allowed(db_session):
    u1 = User(email="user1@test.com")
    u2 = User(email="user2@test.com")
    db_session.add_all([u1, u2])
    db_session.commit()

    acc1 = EmailAccount(user_id=u1.id, provider="gmail", email_address="user1@test.com")
    acc2 = EmailAccount(user_id=u2.id, provider="gmail", email_address="user2@test.com")
    db_session.add_all([acc1, acc2])
    db_session.commit()

    # Insert first email
    eml1 = Email(
        email_account_id=acc1.id,
        message_id="msg123",
        sender="a@b.com",
        recipient="c@d.com"
    )
    db_session.add(eml1)
    db_session.commit()

    # Insert second email with same message_id but different account
    eml2 = Email(
        email_account_id=acc2.id,
        message_id="msg123",
        sender="a@b.com",
        recipient="c@d.com"
    )
    db_session.add(eml2)
    db_session.commit()  # Should succeed!

    assert eml1.id != eml2.id

from unittest.mock import MagicMock
from gmail_client import sync_gmail_messages, GmailAPIError, GmailMessageRef

def test_sync_deduplication_works(db_session, monkeypatch):
    # Create account
    u = User(email="sync@test.com")
    db_session.add(u)
    db_session.commit()
    acc = EmailAccount(user_id=u.id, provider="gmail", email_address="sync@test.com", access_token="fake")
    db_session.add(acc)
    db_session.commit()

    # Mock gmail API
    monkeypatch.setattr("gmail_client.list_message_ids", lambda *a, **k: [GmailMessageRef("gmsg1", "thrd1")])
    monkeypatch.setattr("gmail_client.get_raw_message", lambda *a, **k: b"Message-ID: <msg123@test.com>\r\nSubject: Test\r\nFrom: a@b.com\r\nTo: c@d.com\r\n\r\nBody")
    monkeypatch.setattr("gmail_client.get_raw_messages_batch", lambda token, ids, *a, **k: {i: (b"Message-ID: <msg123@test.com>\r\nSubject: Test\r\nFrom: a@b.com\r\nTo: c@d.com\r\n\r\nBody", None) for i in ids})

    # Run sync first time
    res1 = sync_gmail_messages(acc.id, "fake", db_session)
    assert res1.fetched == 1
    assert res1.persisted == 1
    assert res1.skipped_duplicate == 0

    # Run sync second time
    res2 = sync_gmail_messages(acc.id, "fake", db_session)
    assert res2.fetched == 1
    assert res2.persisted == 0
    assert res2.skipped_duplicate == 1

    # Verify only 1 email in DB
    emails = db_session.query(Email).filter_by(email_account_id=acc.id).all()
    assert len(emails) == 1
