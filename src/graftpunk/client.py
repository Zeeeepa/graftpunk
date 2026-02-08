"""First-class Python API for executing plugin commands.

Provides ``GraftpunkClient`` -- a stateful, context-manager-friendly
client that wraps a single plugin.  Commands are accessible via
attribute access (``client.login()``) or string dispatch
(``client.execute("login")``).

Example::

    from graftpunk.client import GraftpunkClient

    with GraftpunkClient("mysite") as client:
        result = client.login(username="alice")
        invoices = client.invoice.list(status="open")
"""

from __future__ import annotations

from typing import Any

from graftpunk.logging import get_logger
from graftpunk.plugins import get_plugin
from graftpunk.plugins.cli_plugin import (
    CLIPluginProtocol,
    CommandResult,
    CommandSpec,
)

LOG = get_logger(__name__)


class GraftpunkClient:
    """Stateful client for a single plugin.

    Builds a command hierarchy on init from the plugin's
    ``get_commands()`` list.  Top-level commands become
    ``_CommandCallable`` objects; grouped commands are nested
    under ``_GroupProxy`` objects.

    Args:
        plugin_name: The ``site_name`` of the plugin to load.
    """

    def __init__(self, plugin_name: str) -> None:
        self._plugin: CLIPluginProtocol = get_plugin(plugin_name)
        self._session = None
        self._session_dirty = False
        self._last_execution: dict[str, float] = {}

        # Build command hierarchy
        self._top_commands: dict[str, CommandSpec] = {}
        self._groups: dict[str, dict[str, CommandSpec]] = {}

        for spec in self._plugin.get_commands():
            if spec.group is None:
                self._top_commands[spec.name] = spec
            else:
                self._groups.setdefault(spec.group, {})[spec.name] = spec

    # -- attribute-based dispatch ------------------------------------------

    def __getattr__(self, name: str) -> _GroupProxy | _CommandCallable:
        """Return a proxy for a command group or a callable for a command.

        Raises:
            AttributeError: If *name* is not a known command or group.
        """
        if name in self._top_commands:
            return _CommandCallable(self, self._top_commands[name])
        if name in self._groups:
            return _GroupProxy(self, self._groups[name])
        raise AttributeError(f"Plugin '{self._plugin.site_name}' has no command or group '{name}'")

    # -- string dispatch ---------------------------------------------------

    def execute(self, *args: str, **kwargs: Any) -> CommandResult:
        """Execute a command by name.

        Accepts one positional argument for a top-level command or two
        for a grouped command (group, command).

        Args:
            *args: Command path -- ``("login",)`` or ``("invoice", "list")``.
            **kwargs: Keyword arguments forwarded to the command handler.

        Returns:
            The ``CommandResult`` from the handler.
        """
        spec = self._resolve_command(*args)
        return self._execute_command(spec, **kwargs)

    def _resolve_command(self, *args: str) -> CommandSpec:
        """Resolve positional args to a ``CommandSpec``.

        Args:
            *args: One arg (top-level) or two args (group, command).

        Returns:
            The matching ``CommandSpec``.

        Raises:
            AttributeError: If the command or group is unknown.
            ValueError: If the wrong number of args is provided.
        """
        if len(args) == 1:
            name = args[0]
            if name in self._top_commands:
                return self._top_commands[name]
            raise AttributeError(f"Plugin '{self._plugin.site_name}' has no command '{name}'")
        if len(args) == 2:
            group_name, cmd_name = args
            group = self._groups.get(group_name)
            if group is None:
                raise AttributeError(
                    f"Plugin '{self._plugin.site_name}' has no group '{group_name}'"
                )
            spec = group.get(cmd_name)
            if spec is None:
                raise AttributeError(f"Group '{group_name}' has no command '{cmd_name}'")
            return spec
        raise ValueError("execute() takes 1 arg (command) or 2 args (group, command)")

    # -- execution (stub) --------------------------------------------------

    def _execute_command(self, spec: CommandSpec, **kwargs: Any) -> CommandResult:
        """Execute a resolved command.

        Raises:
            NotImplementedError: Always -- implemented in Task 3.
        """
        raise NotImplementedError("Execution pipeline added in Task 3")

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        """Persist dirty session and tear down the plugin."""
        if self._session is not None and self._session_dirty:
            from graftpunk.cache import update_session_cookies

            update_session_cookies(self._session, self._plugin.session_name)
            self._session_dirty = False
        try:
            self._plugin.teardown()
        except Exception:  # noqa: BLE001
            LOG.debug("plugin_teardown_error", exc_info=True)

    def __enter__(self) -> GraftpunkClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class _GroupProxy:
    """Proxy for a command group.

    Attribute access returns a ``_CommandCallable`` for the named
    sub-command.
    """

    __slots__ = ("_client", "_commands")

    def __init__(
        self,
        client: GraftpunkClient,
        commands: dict[str, CommandSpec],
    ) -> None:
        self._client = client
        self._commands = commands

    def __getattr__(self, name: str) -> _CommandCallable:
        """Return a callable for *name*.

        Raises:
            AttributeError: If *name* is not a command in this group.
        """
        spec = self._commands.get(name)
        if spec is None:
            raise AttributeError(
                f"Group has no command '{name}'. Available: {', '.join(sorted(self._commands))}"
            )
        return _CommandCallable(self._client, spec)


class _CommandCallable:
    """A bound command ready to call.

    Calling an instance delegates to
    ``GraftpunkClient._execute_command``.
    """

    __slots__ = ("_client", "_spec")

    def __init__(self, client: GraftpunkClient, spec: CommandSpec) -> None:
        self._client = client
        self._spec = spec

    def __call__(self, **kwargs: Any) -> CommandResult:
        """Execute the command with the given keyword arguments."""
        return self._client._execute_command(self._spec, **kwargs)
