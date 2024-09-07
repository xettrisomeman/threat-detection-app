"""made changes

Revision ID: 6f05fd93598b
Revises: c3415d209dec
Create Date: 2024-03-26 22:25:38.796305

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6f05fd93598b'
down_revision: Union[str, None] = 'c3415d209dec'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
