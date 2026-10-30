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

"""Tab-completion for the engine shell.

The core is :func:`complete` — a pure function (no readline) that, given the
current line and the word being completed, returns candidate completions. It
decides what to complete from the command registry and the command's declared
``arg_kinds``:

- command name (first word(s)) -> matching ``noun verb`` names
- a ``path`` arg -> filesystem paths (``~`` expanded, directory-aware)
- a ``selector`` / ``handle`` arg -> live session handles + wildcards

:class:`ShellCompleter` adapts :func:`complete` to the stdlib ``readline``
completer protocol.
"""

import glob
import os

from picard.cli.engine.dispatch import split_command_name


_WILDCARDS = ('*', 'f*', 'c*', 'a*', 't*', 'm*')
_HANDLE_PREFIXES = ('f', 'c', 'a', 't', 'm')


def _complete_path(text: str) -> list[str]:
    """Filesystem path completions for ``text`` (supports ~ and directories)."""
    expanded = os.path.expanduser(text)
    matches = glob.glob(expanded + '*')
    results = []
    for match in matches:
        # Re-collapse the home dir so the completion matches what the user typed.
        shown = match
        if text.startswith('~'):
            home = os.path.expanduser('~')
            if match.startswith(home):
                shown = '~' + match[len(home) :]
        if os.path.isdir(match):
            shown += os.sep
        results.append(shown)
    return sorted(results)


def _live_handles(session) -> list[str]:
    """All currently-live handles across the known prefixes, via the session."""
    handles = []
    for prefix in _HANDLE_PREFIXES:
        for entity in session.enumerate_prefix(prefix):
            try:
                handles.append(session.handle_for(entity))
            except ValueError:
                continue
    return handles


def complete(line: str, text: str, registry, session) -> list[str]:
    """Return completions for ``text`` given the full ``line`` so far.

    ``text`` is the word being completed (readline's current token); ``line``
    is the whole line up to the cursor.
    """
    # Tokens already on the line (the trailing partial word is ``text``).
    head = line[: len(line) - len(text)]
    tokens = head.split()

    # Completing the command name itself (nothing resolved yet).
    if not tokens:
        names = registry.names() + ['help', 'quit', 'exit']
        return sorted(n for n in names if n.startswith(text))

    # When the first word is on the line and we're completing the second word,
    # offer the verbs of any two-word command sharing that first word. This is
    # needed even when the first word is ITSELF a complete command (e.g.
    # ``cluster`` is a command and also the noun of ``cluster lookup``):
    # ``cluster loo<TAB>`` must still complete to ``lookup``.
    verb_matches: list[str] = []
    if len(tokens) == 1:
        prefix = tokens[0] + ' '
        verb_matches = [
            n[len(prefix) :] for n in registry.names() if n.startswith(prefix) and n[len(prefix) :].startswith(text)
        ]

    # Is the first token (or first two) a known command?
    name, rest = split_command_name(tokens, registry)
    command = registry.get(name)
    if command is None:
        # First word is not a command on its own; only the verb matches apply.
        return sorted(set(verb_matches))

    # We have a command; the number of already-typed args decides the arg index.
    arg_index = len(rest)
    kind = command.arg_kind(arg_index)
    arg_matches: list[str] = []
    if kind == 'path':
        arg_matches = _complete_path(text)
    elif kind in {'selector', 'handle'}:
        options = _live_handles(session)
        if kind == 'selector':
            options = options + list(_WILDCARDS)
        arg_matches = [o for o in set(options) if o.startswith(text)]

    # Merge verb completions (two-word commands) with the one-word command's
    # arg completions, so both ``cluster lookup`` and ``cluster <selector>`` are
    # offered after ``cluster ``.
    return sorted(set(verb_matches) | set(arg_matches))


class ShellCompleter:
    """readline completer adapter around :func:`complete`."""

    def __init__(self, registry, session, get_line_buffer):
        self._registry = registry
        self._session = session
        self._get_line_buffer = get_line_buffer
        self._matches: list[str] = []

    def complete(self, text: str, state: int) -> 'str | None':
        if state == 0:
            line = self._get_line_buffer()
            self._matches = complete(line, text, self._registry, self._session)
        if 0 <= state < len(self._matches):
            return self._matches[state]
        return None
