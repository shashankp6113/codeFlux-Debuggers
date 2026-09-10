"""initial schema: users, email_accounts, emails

Revision ID: cfce780d61b5
Revises: 
Create Date: 2026-09-11 02:07:59.246558

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cfce780d61b5'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create users, email_accounts, and emails tables."""
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index(op.f("ix_users_id"), "users", ["id"], unique=False)

    op.create_table(
        "email_accounts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("email_address", sa.String(), nullable=False),
        sa.Column("access_token", sa.String(), nullable=True),
        sa.Column("refresh_token", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_email_accounts_id"), "email_accounts", ["id"], unique=False
    )

    op.create_table(
        "emails",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email_account_id", sa.Integer(), nullable=False),
        sa.Column("message_id", sa.String(), nullable=True),
        sa.Column("subject", sa.String(), nullable=True),
        sa.Column("sender", sa.String(), nullable=False),
        sa.Column("recipient", sa.String(), nullable=False),
        sa.Column("cc", sa.String(), nullable=True),
        sa.Column("body_text", sa.Text(), nullable=True),
        sa.Column("body_html", sa.Text(), nullable=True),
        sa.Column("raw_headers", sa.Text(), nullable=True),
        sa.Column("received_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["email_account_id"], ["email_accounts.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_emails_id"), "emails", ["id"], unique=False)


def downgrade() -> None:
    """Drop emails, email_accounts, and users tables."""
    op.drop_index(op.f("ix_emails_id"), table_name="emails")
    op.drop_table("emails")
    op.drop_index(op.f("ix_email_accounts_id"), table_name="email_accounts")
    op.drop_table("email_accounts")
    op.drop_index(op.f("ix_users_id"), table_name="users")
    op.drop_table("users")

