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

from test.picardtestcase import PicardTestCase

from picard.cli.engine.selectors import (
    SelectorError,
    parse_selector,
    resolve_selector,
)


class ParseSelectorTest(PicardTestCase):
    def test_single_handle(self):
        terms = parse_selector('a1')
        self.assertEqual(1, len(terms))
        self.assertEqual(('a', 'ordinal', 1), (terms[0].prefix, terms[0].kind, terms[0].value))

    def test_type_wildcard(self):
        (term,) = parse_selector('c*')
        self.assertEqual(('c', 'wildcard', None), (term.prefix, term.kind, term.value))

    def test_universal_wildcard(self):
        (term,) = parse_selector('*')
        self.assertEqual(('', 'wildcard', None), (term.prefix, term.kind, term.value))

    def test_comma_union_with_spaces(self):
        terms = parse_selector('a1, c2 , f3')
        self.assertEqual(['a1', 'c2', 'f3'], [t.raw for t in terms])

    def test_rejects_exclusion(self):
        with self.assertRaises(SelectorError):
            parse_selector('!a2')

    def test_rejects_range(self):
        with self.assertRaises(SelectorError):
            parse_selector('a1-3')

    def test_rejects_unknown_prefix(self):
        with self.assertRaises(SelectorError):
            parse_selector('z1')

    def test_rejects_bare_ordinal(self):
        # Bare-ordinal sticky prefix is full-grammar, not the subset.
        with self.assertRaises(SelectorError):
            parse_selector('a1,2')

    def test_rejects_empty_term(self):
        with self.assertRaises(SelectorError):
            parse_selector('a1,,c2')

    def test_rejects_prefix_without_ordinal(self):
        with self.assertRaises(SelectorError):
            parse_selector('a')


class _FakeWorkspace:
    """Minimal enumerator source keyed by prefix."""

    def __init__(self, **by_prefix):
        self._by_prefix = {k: list(v) for k, v in by_prefix.items()}

    def enumerate_prefix(self, prefix):
        return list(self._by_prefix.get(prefix, ()))


def _registry(mapping):
    """A handle->entity resolver from a dict; missing handles resolve to None."""
    return lambda handle: mapping.get(handle)


class ResolveSelectorTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.a1, self.a2 = object(), object()
        self.c1 = object()
        self.f1, self.f2 = object(), object()
        self.handles = {'a1': self.a1, 'a2': self.a2, 'c1': self.c1, 'f1': self.f1, 'f2': self.f2}
        self.ws = _FakeWorkspace(a=[self.a1, self.a2], c=[self.c1], f=[self.f1, self.f2])

    def _resolve(self, text):
        return resolve_selector(text, _registry(self.handles), self.ws.enumerate_prefix)

    def test_single_handle_hit(self):
        entities, unresolved = self._resolve('a1')
        self.assertEqual([self.a1], entities)
        self.assertEqual([], unresolved)

    def test_single_handle_miss(self):
        entities, unresolved = self._resolve('a9')
        self.assertEqual([], entities)
        self.assertEqual(['a9'], unresolved)

    def test_type_wildcard(self):
        entities, unresolved = self._resolve('a*')
        self.assertEqual([self.a1, self.a2], entities)
        self.assertEqual([], unresolved)

    def test_universal_wildcard_is_top_level(self):
        # f* ∪ c* ∪ a*, first-appearance order (f, then c, then a).
        entities, unresolved = self._resolve('*')
        self.assertEqual([self.f1, self.f2, self.c1, self.a1, self.a2], entities)
        self.assertEqual([], unresolved)

    def test_comma_union(self):
        entities, unresolved = self._resolve('a1,c1')
        self.assertEqual([self.a1, self.c1], entities)
        self.assertEqual([], unresolved)

    def test_union_dedupes_preserving_first_order(self):
        # a1 appears both explicitly and via a*; it must appear once, first.
        entities, _ = self._resolve('a1,a*')
        self.assertEqual([self.a1, self.a2], entities)

    def test_mixed_hit_and_miss(self):
        entities, unresolved = self._resolve('a1,a9,c1')
        self.assertEqual([self.a1, self.c1], entities)
        self.assertEqual(['a9'], unresolved)

    def test_resolved_empty_vs_unresolved(self):
        # Valid wildcard over an empty namespace: resolved-empty, NOT unresolved.
        ws = _FakeWorkspace(a=[])
        entities, unresolved = resolve_selector('a*', _registry({}), ws.enumerate_prefix)
        self.assertEqual([], entities)
        self.assertEqual([], unresolved)
