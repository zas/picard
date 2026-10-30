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

"""Selector parsing and resolution.

A selector is a compact reference to a set of working-set entities — the same
syntax a human types at the console and an agent passes in an MCP ``selector``
argument. See ``docs/CommandEngine.md`` for the full target grammar.

This module implements a documented SUBSET of that grammar:

- a single handle: ``a1``, ``c2``, ``f3``
- a type wildcard: ``a*`` (all albums), ``c*``, ``f*``, ``t*``
- the universal wildcard: ``*`` (all top-level objects)
- a comma-separated union of the above: ``a1, c2, f3``

Not yet implemented (reserved; the parse/resolve shape leaves room for them so
they slot in without reshaping): bare-ordinal sticky prefixes (``a1,2,3``),
ranges (``a1-3``) and exclusion (``!a2``). Attempting that syntax raises
:class:`SelectorError` rather than silently mis-parsing.

Resolution returns ``(entities, unresolved)``:
- *entities*: the live entities the selector matched (de-duplicated, order of
  first appearance).
- *unresolved*: tokens that parsed but matched no live entity (e.g. a handle
  that was never minted or whose entity has been removed). A non-empty
  ``unresolved`` means the caller under-acted; it is surfaced to the frontend
  (console warns, MCP returns it) rather than silently dropped.
"""

from collections.abc import (
    Callable,
    Iterable,
)
from dataclasses import dataclass
from typing import Any


# Handle prefixes the subset recognises. Kept explicit so an unknown prefix is
# a clear error. Extend here (plus the enumerator) as entity kinds are added.
KNOWN_PREFIXES = frozenset({'f', 'c', 'a', 't', 'm', 'v', 'd', 'k'})

# Prefixes that make up the universal top-level set ``*`` (mirrors the GUI panes:
# unclustered files, clusters, albums/NAT). NOT tracks.
TOP_LEVEL_PREFIXES = ('f', 'c', 'a')


# An enumerator maps a handle prefix to the live entities of that kind, in a
# stable order. Injected so this module does not depend on Workspace/core.
Enumerator = Callable[[str], Iterable[Any]]

# Resolves a handle string to its entity, or None if unknown/expired
# (HandleRegistry.resolve satisfies this).
HandleResolver = Callable[[str], Any]


class SelectorError(ValueError):
    """Raised when a selector string is malformed or uses unsupported syntax."""


@dataclass(frozen=True)
class Term:
    """One parsed selector term.

    ``negate`` and ``kind == 'range'`` are part of the full grammar and are not
    produced by the current subset parser, but the shape is fixed here so the
    resolver's union/difference algorithm already accommodates them.
    """

    prefix: str  # a handle prefix, or '' for a bare universal '*'
    kind: str  # 'ordinal' | 'wildcard' | 'range'
    value: Any  # int (ordinal) | None (wildcard) | tuple[int, int] (range)
    negate: bool = False
    raw: str = ''  # original token text, for unresolved reporting


def parse_selector(text: str) -> list[Term]:
    """Parse a selector string into a list of :class:`Term`.

    Implements the subset described in the module docstring. Raises
    :class:`SelectorError` on malformed input or unsupported (reserved) syntax.
    """
    if text is None:
        raise SelectorError("selector is None")
    terms: list[Term] = []
    for raw_token in text.split(','):
        token = raw_token.strip()
        if not token:
            raise SelectorError(f"empty selector term in {text!r}")
        terms.append(_parse_token(token))
    if not terms:
        raise SelectorError("empty selector")
    return terms


def _parse_token(token: str) -> Term:
    # Reserved syntax — reject explicitly (clearer than a confusing parse error).
    if token.startswith('!'):
        raise SelectorError(f"exclusion ('!') is not supported yet: {token!r}")
    if '-' in token:
        raise SelectorError(f"ranges ('-') are not supported yet: {token!r}")

    # Universal wildcard.
    if token == '*':
        return Term(prefix='', kind='wildcard', value=None, raw=token)

    prefix, rest = _split_prefix(token)
    if prefix is None:
        raise SelectorError(f"selector term must start with a type prefix: {token!r}")
    if prefix not in KNOWN_PREFIXES:
        raise SelectorError(f"unknown selector prefix {prefix!r} in {token!r}")

    if rest == '*':
        return Term(prefix=prefix, kind='wildcard', value=None, raw=token)
    if rest.isdigit():
        return Term(prefix=prefix, kind='ordinal', value=int(rest), raw=token)
    if rest == '':
        raise SelectorError(f"selector term {token!r} has a prefix but no ordinal or '*'")
    # Bare-ordinal sticky prefixes are part of the full grammar, not the subset.
    raise SelectorError(f"malformed selector term: {token!r}")


def _split_prefix(token: str) -> 'tuple[str | None, str]':
    """Split a leading alphabetic prefix from the rest: ``a12`` -> ('a', '12')."""
    i = 0
    while i < len(token) and token[i].isalpha():
        i += 1
    if i == 0:
        return None, token
    return token[:i], token[i:]


def resolve_selector(
    text: str,
    resolve_handle: HandleResolver,
    enumerate_prefix: Enumerator,
) -> 'tuple[list[Any], list[str]]':
    """Resolve ``text`` to ``(entities, unresolved)``.

    ``resolve_handle(handle)`` returns the entity for a handle or None.
    ``enumerate_prefix(prefix)`` yields the live entities for a wildcard.

    Entities are de-duplicated by identity, preserving first-appearance order.
    Tokens that match no live entity are collected in ``unresolved``.
    """
    terms = parse_selector(text)

    entities: list[Any] = []
    seen: set[int] = set()
    unresolved: list[str] = []

    def add(entity: Any) -> None:
        key = id(entity)
        if key not in seen:
            seen.add(key)
            entities.append(entity)

    for term in terms:
        if term.kind == 'ordinal':
            handle = f"{term.prefix}{term.value}"
            entity = resolve_handle(handle)
            if entity is None:
                unresolved.append(term.raw)
            else:
                add(entity)
        elif term.kind == 'wildcard':
            prefixes = (term.prefix,) if term.prefix else TOP_LEVEL_PREFIXES
            for prefix in prefixes:
                for entity in enumerate_prefix(prefix):
                    add(entity)
        else:  # pragma: no cover - 'range' not produced by the subset parser
            raise SelectorError(f"unsupported term kind: {term.kind}")

    return entities, unresolved
