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

"""Interactive console for the command engine (picard-cli shell).

A human-oriented REPL over a headless :class:`LocalEngineSession`: read a line,
dispatch it to a command, render the structured result. This is the first
frontend of the command engine (see docs/CommandEngine.md) — primarily for
experimenting with and debugging the engine. Lines use the ``<noun> <verb>``
vocabulary, e.g.::

    picard> file add ~/Music/incoming/*.flac
    picard> cluster
    picard> cluster lookup
    picard> match c1 m2
    picard> save

``help`` lists commands; ``quit``/``exit`` (or EOF / Ctrl-D) leaves.
"""

from argparse import ArgumentParser

from picard.cli.base import ExitCode
from picard.cli.subcommand import Subcommand


_PROMPT = 'picard> '


def _setup_readline(registry, session) -> None:
    """Enable tab-completion (handles + file paths) if readline is available."""
    try:
        import readline
    except ImportError:  # e.g. some Windows Pythons without pyreadline
        return
    from picard.cli.engine.completion import ShellCompleter

    completer = ShellCompleter(registry, session, readline.get_line_buffer)
    readline.set_completer(completer.complete)
    # Complete whole tokens: do not break on characters common in paths/handles
    # (default delims include '/', '-', '~', etc. which would split paths).
    readline.set_completer_delims(' \t\n')
    # 'libedit' (macOS) uses a different bind syntax than GNU readline.
    if 'libedit' in getattr(readline, '__doc__', ''):
        readline.parse_and_bind('bind ^I rl_complete')
    else:
        readline.parse_and_bind('tab: complete')


class ShellSubcommand(Subcommand):
    def __init__(self):
        super().__init__(
            name='shell',
            help='interactive command engine console (experimental)',
            examples=('shell',),
        )

    def setup_parser(self, parser: ArgumentParser):
        parser.description = 'Start an interactive console to drive the tagging engine (experimental).'
        parser.set_defaults(run_command=_run_shell)


def _print_help(registry, output) -> None:
    output.print("Commands:")
    for name in registry.names():
        cmd = registry.get(name)
        output.print(f"  {output.d_command(name):<28} {cmd.help}")
    output.print(f"  {output.d_command('help'):<28} Show this help.")
    output.print(f"  {output.d_command('quit'):<28} Leave the shell (also: exit, Ctrl-D).")


def run_repl(session, registry, output, read_line) -> None:
    """Run the read-dispatch-render loop.

    ``read_line`` is a callable returning the next input line, or raising
    EOFError at end of input. Factored out so it can be driven by a scripted
    input in tests (not only an interactive terminal).
    """
    # Local import: dispatch/render pull in the engine; keep shell import light.
    from picard.cli.engine.dispatch import dispatch
    from picard.cli.engine.render import render_result

    while True:
        try:
            line = read_line()
        except EOFError:
            output.nl()
            return
        line = line.strip()
        if not line:
            continue
        head = line.split(None, 1)[0]
        if head in {'quit', 'exit'}:
            return
        if head == 'help':
            _print_help(registry, output)
            continue
        result = dispatch(session, registry, line)
        render_result(result, output)


def _run_shell(args):
    from picard.cli._bootstrap import (
        init_logging,
        is_color_disabled,
    )
    from picard.cli.engine.builtins import register_builtins
    from picard.cli.engine.commands import EngineCommandRegistry
    from picard.cli.engine.session import LocalEngineSession
    from picard.cli.headless import HeadlessTagger
    from picard.cli.output import CliOutput

    config_file = getattr(args, 'config_file', None)
    app = HeadlessTagger([], config_file=config_file)
    init_logging(args)
    output = CliOutput(color=False if is_color_disabled(args) else None)

    registry = EngineCommandRegistry()
    register_builtins(registry)
    session = LocalEngineSession(app)

    _setup_readline(registry, session)

    output.print(output.dim("Picard engine shell — type 'help', 'quit' to exit."))

    def read_line():
        return input(_PROMPT)

    try:
        run_repl(session, registry, output, read_line)
    finally:
        app.run_cleanup()
    return ExitCode.SUCCESS
