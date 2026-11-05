#
# Copyright (C) 2026 Laurent Monin
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

"""Command declarations, the command registry, and the session interface.

A command is declared ONCE (:class:`EngineCommand`) with a ``noun verb`` name,
its backend availability, and a ``run`` callable. Both frontends (console REPL,
MCP) read the same registry, so there is one vocabulary.

:class:`EngineSession` is the INTERFACE commands run against. Commands are
written against this protocol and do not know whether they run in-process
(``LocalEngineSession``, headless) or against a running GUI over a transport (a
future ``RemoteEngineSession``). Keeping it a Protocol now is the single
concession to that two-backend future.

See ``docs/CommandEngine.md``.
"""

from collections.abc import (
    Callable,
    Iterable,
    Sequence,
)
from dataclasses import (
    dataclass,
    field,
)
from enum import Enum
from typing import (
    Any,
    Protocol,
    runtime_checkable,
)

from picard.cli.engine.result import EngineResult


class Availability(Enum):
    """Which backend(s) a command supports."""

    BOTH = 'both'  # runs on core/Workspace — headless or GUI
    GUI_ONLY = 'gui'  # only meaningful against a running GUI (views, window, ...)


@runtime_checkable
class EngineSession(Protocol):
    """What a command is handed to do its work.

    Implemented in-process by ``LocalEngineSession`` (headless); a future
    ``RemoteEngineSession`` satisfies the same protocol by proxying to a running
    GUI. Commands depend only on this surface, never on a concrete tagger.
    """

    def resolve(self, selector: 'str | Sequence[str]') -> 'tuple[list[Any], list[str]]':
        """Resolve a selector to ``(entities, unresolved_tokens)``.

        ``selector`` is a string, or the words a command line split it into
        (``a1, c2`` arrives as ``['a1,', 'c2']``).
        """
        ...

    def resolve_targets(self, selector: str) -> list[Any]:
        """Resolve one selector term to the places it names, unexpanded (``u`` stays a bucket)."""
        ...

    def handle_for(self, entity: Any) -> str:
        """Return (minting if needed) the session handle for ``entity``."""
        ...

    def list_options(self, pattern: 'str | None' = None) -> 'list[dict[str, Any]]':
        """Describe the options matching ``pattern`` (all those not at their default without one)."""
        ...

    def describe_option(self, name: str) -> 'dict[str, Any]':
        """Describe one option: value, default, type, title and where the value comes from."""
        ...

    def path_of(self, handle: str) -> 'str | None':
        """Where the entity of ``handle`` currently sits, as a selector path (or None)."""
        ...

    def path_segments(self, base: str) -> 'list[str]':
        """The path segments that can follow ``base`` (``a1`` -> ``d*``, ``t*``, ...), for completion."""
        ...

    def enumerate_prefix(self, prefix: str) -> Iterable[Any]:
        """Yield the live entities of a handle prefix (for wildcards / ls)."""
        ...

    def set_candidates(self, target: Any, candidates: list[Any]) -> list[str]:
        """Replace the lookup candidates for ``target``; return their handles."""
        ...

    def candidates_for(self, target: Any) -> list[Any]:
        """Return the current candidates held for ``target`` (may be empty)."""
        ...

    def run_until_idle(self, timeout: float | None = None) -> bool:
        """Drain async work (thread pools, pending requests) to completion."""
        ...

    @property
    def is_gui(self) -> bool:
        """True if this session drives a GUI backend (enables gui-only commands)."""
        ...


# A command's implementation: given the session and parsed args, return a
# result. It must not print or touch transport.
CommandFunc = Callable[[EngineSession, 'dict[str, Any]'], EngineResult]


@dataclass(frozen=True)
class EngineCommand:
    """A single declared command.

    ``name`` is the full ``noun verb`` (e.g. ``"album save"``). ``run`` receives
    the session and a dict of parsed arguments and returns an EngineResult.
    """

    name: str
    run: CommandFunc
    help: str = ''
    availability: Availability = Availability.BOTH
    # Names of positional args this command expects, for frontends to parse/
    # document. Kept as simple strings; there is no typed-parameter layer.
    args: tuple[str, ...] = field(default_factory=tuple)
    # Completion hint per positional arg, parallel to ``args``: one of
    # 'path' (filesystem path), 'device' (CD/DVD drive), 'selector' (handle
    # selector / wildcard), 'handle' (a single handle), or '' (no completion).
    # Used by the shell's
    # tab-completer. Missing entries default to no completion.
    arg_kinds: tuple[str, ...] = field(default_factory=tuple)
    # True for a command whose effect on disk is hard to undo (e.g. ``trash``).
    # The engine itself never prompts; an interactive frontend should ask for
    # confirmation before running such a command, and an automated one can apply
    # its own policy.
    destructive: bool = False

    def arg_kind(self, index: int) -> str:
        """Completion kind for the word at ``index`` (''/unknown).

        The last declared arg absorbs every remaining word (see the dispatcher),
        so its kind applies to all the words from there on: ``file add a b <TAB>``
        still completes a path, and ``move f1 f2 <TAB>`` a selector.
        """
        if index < 0 or not self.arg_kinds:
            return ''
        return self.arg_kinds[min(index, len(self.arg_kinds) - 1)]

    @property
    def noun(self) -> str:
        return self.name.split(' ', 1)[0]

    @property
    def verb(self) -> str:
        parts = self.name.split(' ', 1)
        return parts[1] if len(parts) > 1 else ''


class EngineCommandRegistry:
    """Holds the declared commands; both frontends read it."""

    def __init__(self):
        self._commands: dict[str, EngineCommand] = {}

    def register(self, command: EngineCommand) -> EngineCommand:
        """Register ``command``. Raises ValueError on a duplicate name."""
        if command.name in self._commands:
            raise ValueError(f"command already registered: {command.name!r}")
        self._commands[command.name] = command
        return command

    def get(self, name: str) -> 'EngineCommand | None':
        return self._commands.get(name)

    def names(self) -> list[str]:
        """Registered command names, sorted."""
        return sorted(self._commands)

    def available(self, is_gui: bool) -> list[EngineCommand]:
        """Commands runnable on a backend (gui-only ones only when is_gui)."""
        return [cmd for cmd in self._commands.values() if cmd.availability is Availability.BOTH or is_gui]

    def __contains__(self, name: str) -> bool:
        return name in self._commands

    def __len__(self) -> int:
        return len(self._commands)
