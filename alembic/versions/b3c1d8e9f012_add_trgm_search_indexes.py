"""Add pg_trgm search indexes for fast ILIKE search

Revision ID: b3c1d8e9f012
Revises: ae2f6293ca2d
Create Date: 2026-02-26 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b3c1d8e9f012'
down_revision: Union[str, Sequence[str], None] = 'ae2f6293ca2d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable pg_trgm extension (required for GIN trigram indexes)
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    # GIN trigram indexes — make ILIKE '%query%' use index instead of full scan
    op.execute("CREATE INDEX IF NOT EXISTS idx_documents_code_trgm ON documents USING GIN (code gin_trgm_ops)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_documents_name_trgm ON documents USING GIN (name gin_trgm_ops)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_pages_designation_trgm ON pages USING GIN (designation gin_trgm_ops)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_pages_name_trgm ON pages USING GIN (name gin_trgm_ops)")

    # Standard B-tree indexes for joins and filtering
    op.execute("CREATE INDEX IF NOT EXISTS idx_documents_category_id ON documents (category_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_pages_document_id ON pages (document_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_categories_group_id ON categories (group_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_documents_code_trgm")
    op.execute("DROP INDEX IF EXISTS idx_documents_name_trgm")
    op.execute("DROP INDEX IF EXISTS idx_pages_designation_trgm")
    op.execute("DROP INDEX IF EXISTS idx_pages_name_trgm")
    op.execute("DROP INDEX IF EXISTS idx_documents_category_id")
    op.execute("DROP INDEX IF EXISTS idx_pages_document_id")
    op.execute("DROP INDEX IF EXISTS idx_categories_group_id")