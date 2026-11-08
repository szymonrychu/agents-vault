"""Database access of agents-vault."""

from agents_common.db.migrate import run_migrations

from agents_vault.settings import Settings


def migrate(settings: Settings) -> list[str]:
    """Apply pending migration files under the advisory lock; return the names applied."""
    return run_migrations(settings.database_url.get_secret_value(), "agents_vault")
