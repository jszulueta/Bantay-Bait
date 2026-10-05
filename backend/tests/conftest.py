import pytest

from app import store


@pytest.fixture(autouse=True)
def temp_check_log(tmp_path, monkeypatch):
    """Every test gets its own empty SQLite check log and admin credentials."""
    store.configure(f"sqlite:///{tmp_path / 'checks.db'}")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-password")
    monkeypatch.setenv("ADMIN_SECRET", "test-secret-for-signing-tokens")
    from app import admin
    admin._failures.clear()
    yield
