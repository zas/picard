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

import io
from unittest.mock import MagicMock

from test.picardtestcase import PicardTestCase

from picard.album import Album
from picard.cli.engine.builtins import register_builtins
from picard.cli.engine.commands import EngineCommandRegistry
from picard.cli.engine.render import render_result
from picard.cli.engine.result import (
    EngineItemResult,
    EngineResult,
)
from picard.cli.engine.session import LocalEngineSession
from picard.cli.output import CliOutput
from picard.cli.shell import run_repl
from picard.workspace import workspace


def _output():
    buf = io.StringIO()
    return CliOutput(stdout=buf, stderr=buf, color=False), buf


class RenderResultTest(PicardTestCase):
    def test_render_items_with_handles(self):
        out, buf = _output()
        result = EngineResult(
            items=[EngineItemResult('a1', 'matched', {'title': 'OK Computer'})],
            mints=['a1'],
        )
        render_result(result, out)
        text = buf.getvalue()
        self.assertIn('a1', text)
        self.assertIn('matched', text)
        self.assertIn('OK Computer', text)
        self.assertIn('minted', text)

    def test_render_item_shows_type_mbid(self):
        out, buf = _output()
        result = EngineResult(
            items=[
                EngineItemResult(
                    'a1',
                    'listed',
                    {'entity_type': 'release', 'mbid': 'rel-123', 'title': 'OK Computer'},
                )
            ],
        )
        render_result(result, out)
        self.assertIn('release:rel-123', buf.getvalue())

    def test_render_failure(self):
        out, buf = _output()
        render_result(EngineResult.failure('boom', unresolved=['a9']), out)
        text = buf.getvalue()
        self.assertIn('boom', text)
        self.assertIn('a9', text)

    def test_render_candidates_marks_applied(self):
        out, buf = _output()
        result = EngineResult(
            items=[
                EngineItemResult(
                    'c1',
                    'matched',
                    {
                        'candidates': [
                            {
                                'handle': 'm1',
                                'entity_type': 'release',
                                'mbid': 'rel-abc',
                                'title': 'Best',
                                'similarity': 0.9,
                                'applied': True,
                            },
                            {'handle': 'm2', 'title': 'Other', 'similarity': 0.5},
                        ]
                    },
                )
            ],
        )
        render_result(result, out)
        text = buf.getvalue()
        self.assertIn('m1', text)
        self.assertIn('Best', text)
        self.assertIn('release:rel-abc', text)
        self.assertIn('* ', text)  # applied marker

    def test_render_empty(self):
        out, buf = _output()
        render_result(EngineResult(), out)
        self.assertIn('(nothing)', buf.getvalue())


class RunReplTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.out, self.buf = _output()
        self.reg = EngineCommandRegistry()
        register_builtins(self.reg)
        self.session = LocalEngineSession(MagicMock())
        ws = workspace()
        ws.albums = {'rel-1': Album('rel-1')}

    def _lines(self, *lines):
        it = iter(lines)

        def read_line():
            try:
                return next(it)
            except StopIteration:
                raise EOFError from None

        return read_line

    def test_quit_leaves(self):
        run_repl(self.session, self.reg, self.out, self._lines('quit'))
        # Should return without error; nothing dispatched.
        self.assertNotIn('unknown command', self.buf.getvalue())

    def test_eof_leaves(self):
        run_repl(self.session, self.reg, self.out, self._lines())  # immediate EOF
        # No exception; loop exits cleanly.

    def test_blank_lines_skipped(self):
        run_repl(self.session, self.reg, self.out, self._lines('', '   ', 'quit'))
        self.assertEqual('', self.buf.getvalue().replace('\n', ''))

    def test_help_lists_commands(self):
        run_repl(self.session, self.reg, self.out, self._lines('help', 'quit'))
        text = self.buf.getvalue()
        self.assertIn('ls', text)
        self.assertIn('cluster lookup', text)
        self.assertIn('quit', text)

    def test_ls_dispatched_and_rendered(self):
        run_repl(self.session, self.reg, self.out, self._lines('ls', 'quit'))
        # The album handle a1 is minted and rendered.
        self.assertIn('a1', self.buf.getvalue())

    def test_unknown_command_rendered_as_error(self):
        run_repl(self.session, self.reg, self.out, self._lines('bogus thing', 'quit'))
        self.assertIn('unknown command', self.buf.getvalue())

    def test_ctrl_c_at_prompt_cancels_line_and_continues(self):
        # Ctrl-C at the prompt raises KeyboardInterrupt from read_line; the loop
        # must swallow it, return to the prompt, and NOT exit or crash.
        calls = iter([KeyboardInterrupt(), 'ls', 'quit'])

        def read_line():
            value = next(calls)
            if isinstance(value, BaseException):
                raise value
            return value

        run_repl(self.session, self.reg, self.out, read_line)
        # The command after the interrupt still ran (a1 rendered).
        self.assertIn('a1', self.buf.getvalue())

    def test_ctrl_c_during_command_is_caught(self):
        # Ctrl-C while a command runs (dispatch) must abort that command and
        # return to the prompt rather than propagating out of run_repl.
        # KeyboardInterrupt is a BaseException, so dispatch's `except Exception`
        # does not swallow it; run_repl must catch it around dispatch.
        from picard.cli.engine.commands import EngineCommand

        def boom(session, args):
            raise KeyboardInterrupt()

        self.reg.register(EngineCommand(name='hang', run=boom))
        run_repl(self.session, self.reg, self.out, self._lines('hang', 'quit'))
        self.assertIn('interrupted', self.buf.getvalue())
