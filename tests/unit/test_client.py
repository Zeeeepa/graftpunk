"""Tests for graftpunk.client — GraftpunkClient skeleton."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from graftpunk.client import GraftpunkClient, _CommandCallable, _GroupProxy
from graftpunk.plugins.cli_plugin import CommandSpec

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_spec(name: str, group: str | None = None) -> CommandSpec:
    """Create a minimal CommandSpec for testing."""
    return CommandSpec(name=name, handler=lambda **kw: kw, group=group)


def _make_plugin(
    site_name: str = "testsite",
    commands: list[CommandSpec] | None = None,
) -> MagicMock:
    """Create a mock plugin with configurable commands."""
    plugin = MagicMock()
    plugin.site_name = site_name
    plugin.session_name = site_name
    plugin.get_commands.return_value = commands or []
    return plugin


# ---------------------------------------------------------------------------
# GraftpunkClient initialisation
# ---------------------------------------------------------------------------


class TestClientInit:
    """Tests for GraftpunkClient.__init__."""

    @patch("graftpunk.client.get_plugin")
    def test_creates_client(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_plugin(commands=[])
        client = GraftpunkClient("testsite")
        mock_get.assert_called_once_with("testsite")
        assert client._plugin.site_name == "testsite"

    @patch("graftpunk.client.get_plugin")
    def test_builds_top_commands(self, mock_get: MagicMock) -> None:
        specs = [_make_spec("login"), _make_spec("status")]
        mock_get.return_value = _make_plugin(commands=specs)
        client = GraftpunkClient("testsite")
        assert set(client._top_commands) == {"login", "status"}
        assert client._groups == {}

    @patch("graftpunk.client.get_plugin")
    def test_builds_grouped_commands(self, mock_get: MagicMock) -> None:
        specs = [
            _make_spec("list", group="invoice"),
            _make_spec("create", group="invoice"),
            _make_spec("login"),
        ]
        mock_get.return_value = _make_plugin(commands=specs)
        client = GraftpunkClient("testsite")
        assert "login" in client._top_commands
        assert "invoice" in client._groups
        assert set(client._groups["invoice"]) == {"list", "create"}


# ---------------------------------------------------------------------------
# Attribute access
# ---------------------------------------------------------------------------


class TestClientAttributeAccess:
    """Tests for GraftpunkClient.__getattr__."""

    @patch("graftpunk.client.get_plugin")
    def test_top_command_returns_callable(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_plugin(commands=[_make_spec("login")])
        client = GraftpunkClient("testsite")
        result = client.login
        assert isinstance(result, _CommandCallable)

    @patch("graftpunk.client.get_plugin")
    def test_group_returns_proxy(self, mock_get: MagicMock) -> None:
        specs = [_make_spec("list", group="invoice")]
        mock_get.return_value = _make_plugin(commands=specs)
        client = GraftpunkClient("testsite")
        result = client.invoice
        assert isinstance(result, _GroupProxy)

    @patch("graftpunk.client.get_plugin")
    def test_unknown_raises_attribute_error(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_plugin(commands=[])
        client = GraftpunkClient("testsite")
        with pytest.raises(AttributeError, match="no command or group 'nope'"):
            _ = client.nope


# ---------------------------------------------------------------------------
# _GroupProxy
# ---------------------------------------------------------------------------


class TestGroupProxy:
    """Tests for _GroupProxy.__getattr__."""

    @patch("graftpunk.client.get_plugin")
    def test_group_command_returns_callable(self, mock_get: MagicMock) -> None:
        specs = [_make_spec("list", group="invoice")]
        mock_get.return_value = _make_plugin(commands=specs)
        client = GraftpunkClient("testsite")
        proxy = client.invoice
        result = proxy.list
        assert isinstance(result, _CommandCallable)

    @patch("graftpunk.client.get_plugin")
    def test_group_unknown_raises_attribute_error(self, mock_get: MagicMock) -> None:
        specs = [_make_spec("list", group="invoice")]
        mock_get.return_value = _make_plugin(commands=specs)
        client = GraftpunkClient("testsite")
        proxy = client.invoice
        with pytest.raises(AttributeError, match="no command 'nope'"):
            _ = proxy.nope


# ---------------------------------------------------------------------------
# _CommandCallable
# ---------------------------------------------------------------------------


class TestCommandCallable:
    """Tests for _CommandCallable.__call__."""

    @patch("graftpunk.client.get_plugin")
    def test_call_delegates_to_execute_command(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_plugin(commands=[_make_spec("login")])
        client = GraftpunkClient("testsite")
        callable_cmd = client.login
        # _execute_command raises NotImplementedError in the skeleton
        with pytest.raises(NotImplementedError):
            callable_cmd()


# ---------------------------------------------------------------------------
# _resolve_command (string dispatch)
# ---------------------------------------------------------------------------


class TestResolveCommand:
    """Tests for GraftpunkClient._resolve_command."""

    @patch("graftpunk.client.get_plugin")
    def test_resolve_top_level(self, mock_get: MagicMock) -> None:
        spec = _make_spec("login")
        mock_get.return_value = _make_plugin(commands=[spec])
        client = GraftpunkClient("testsite")
        assert client._resolve_command("login") is spec

    @patch("graftpunk.client.get_plugin")
    def test_resolve_grouped(self, mock_get: MagicMock) -> None:
        spec = _make_spec("list", group="invoice")
        mock_get.return_value = _make_plugin(commands=[spec])
        client = GraftpunkClient("testsite")
        assert client._resolve_command("invoice", "list") is spec

    @patch("graftpunk.client.get_plugin")
    def test_resolve_unknown_top_level(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_plugin(commands=[])
        client = GraftpunkClient("testsite")
        with pytest.raises(AttributeError, match="no command 'nope'"):
            client._resolve_command("nope")

    @patch("graftpunk.client.get_plugin")
    def test_resolve_unknown_group(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_plugin(commands=[])
        client = GraftpunkClient("testsite")
        with pytest.raises(AttributeError, match="no group 'nope'"):
            client._resolve_command("nope", "cmd")

    @patch("graftpunk.client.get_plugin")
    def test_resolve_unknown_group_command(self, mock_get: MagicMock) -> None:
        specs = [_make_spec("list", group="invoice")]
        mock_get.return_value = _make_plugin(commands=specs)
        client = GraftpunkClient("testsite")
        with pytest.raises(AttributeError, match="no command 'nope'"):
            client._resolve_command("invoice", "nope")

    @patch("graftpunk.client.get_plugin")
    def test_resolve_bad_arg_count(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_plugin(commands=[])
        client = GraftpunkClient("testsite")
        with pytest.raises(ValueError, match="1 arg .* or 2 args"):
            client._resolve_command("a", "b", "c")


# ---------------------------------------------------------------------------
# execute (string dispatch entry point)
# ---------------------------------------------------------------------------


class TestExecute:
    """Tests for GraftpunkClient.execute string dispatch."""

    @patch("graftpunk.client.get_plugin")
    def test_execute_delegates(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_plugin(commands=[_make_spec("login")])
        client = GraftpunkClient("testsite")
        with pytest.raises(NotImplementedError):
            client.execute("login")


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


class TestContextManager:
    """Tests for __enter__ and __exit__."""

    @patch("graftpunk.client.get_plugin")
    def test_enter_returns_self(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_plugin(commands=[])
        client = GraftpunkClient("testsite")
        assert client.__enter__() is client

    @patch("graftpunk.client.get_plugin")
    def test_exit_calls_close(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_plugin(commands=[])
        client = GraftpunkClient("testsite")
        with client:
            pass
        # teardown should have been called
        client._plugin.teardown.assert_called_once()

    @patch("graftpunk.client.get_plugin")
    def test_close_handles_teardown_exception(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_plugin(commands=[])
        client = GraftpunkClient("testsite")
        client._plugin.teardown.side_effect = RuntimeError("boom")
        # Should not raise
        client.close()
