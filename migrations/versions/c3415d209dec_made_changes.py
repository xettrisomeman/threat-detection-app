"""made changes

Revision ID: c3415d209dec
Revises: bf5262d0896d
Create Date: 2024-03-26 22:22:31.503574

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3415d209dec'
down_revision: Union[str, None] = 'bf5262d0896d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
