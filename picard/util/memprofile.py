# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2026 Picard contributors
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

"""Opt-in memory profiling instrumentation.

All facilities in this module are gated behind ``DebugOpt.MEMORY`` and are
effectively no-ops (a single boolean check) when that option is disabled, so
they are safe to leave in production code paths.

Enable at runtime with::

    picard --debug-opts=memory

The goal is to *measure before changing*: attribute allocations to source
lines, track object retention, and produce a memory-over-time curve for long
running operations, using only the Python standard library (``tracemalloc``,
``gc``, ``sys``) so no external profiler is required.

Usage
-----

Wrap a suspected hot path::

    from picard.util.memprofile import memory_snapshot

    with memory_snapshot("use original values", n=len(objects)):
        do_bulk_operation()

This logs, only when the option is enabled:
  - net traced memory delta for the block
  - the top allocating source lines (diffed against the block entry)

For retention / leak checks across repeated operations::

    from picard.util.memprofile import log_object_counts

    log_object_counts("after bulk edit")

For a background memory-over-time curve during long operations::

    from picard.util.memprofile import MemorySampler

    sampler = MemorySampler(interval=0.5)
    sampler.start()
    ...
    sampler.stop()
"""

from collections.abc import Generator
from contextlib import contextmanager
import gc
import sys
import threading
import time
import tracemalloc

from picard import log
from picard.debug_opts import DebugOpt


# Number of frames tracemalloc keeps per allocation. More frames give better
# attribution (full retention path) at the cost of memory/CPU while tracing.
_TRACEMALLOC_FRAMES = 25

# How many top entries to log in snapshot diffs.
_TOP_STATS = 25


def is_enabled() -> bool:
    """Return True if memory profiling is enabled."""
    return DebugOpt.MEMORY.enabled


def ensure_tracing() -> bool:
    """Start tracemalloc if the MEMORY option is enabled and it is not already
    running.

    Returns True if tracing is active after the call, False otherwise. Safe to
    call repeatedly; only starts tracing once.
    """
    if not DebugOpt.MEMORY.enabled:
        return False
    if not tracemalloc.is_tracing():
        tracemalloc.start(_TRACEMALLOC_FRAMES)
        log.debug("memprofile: tracemalloc started with %d frames", _TRACEMALLOC_FRAMES)
    return True


def _format_bytes(num: float) -> str:
    """Human-readable byte size."""
    step = 1024.0
    for unit in ('B', 'KiB', 'MiB', 'GiB'):
        if abs(num) < step:
            return f"{num:.1f} {unit}"
        num /= step
    return f"{num:.1f} TiB"


@contextmanager
def memory_snapshot(label: str, *, n: int | None = None, top: int = _TOP_STATS) -> Generator[None]:
    """Diff traced memory allocations around a block and log the top allocators.

    When ``DebugOpt.MEMORY`` is disabled this is a near-zero-overhead no-op.

    Args:
        label: Human-readable name for the profiled block.
        n: Optional workload size (e.g. number of objects) logged alongside
            the result so growth can be compared across runs.
        top: Number of top allocating source lines to log.
    """
    if not ensure_tracing():
        yield
        return

    # Take a filtered snapshot to reduce noise from tracemalloc itself.
    snap_before = tracemalloc.take_snapshot()
    current_before, _peak_before = tracemalloc.get_traced_memory()
    t0 = time.perf_counter_ns()

    yield

    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000
    current_after, peak_after = tracemalloc.get_traced_memory()
    snap_after = tracemalloc.take_snapshot()

    net = current_after - current_before
    suffix = f" (n={n})" if n is not None else ""
    log.debug(
        "memprofile[%s]%s: net=%s peak=%s elapsed=%.1f ms",
        label,
        suffix,
        _format_bytes(net),
        _format_bytes(peak_after),
        elapsed_ms,
    )

    stats = snap_after.compare_to(snap_before, 'lineno')
    log.debug("memprofile[%s]: top %d allocating lines:", label, top)
    for stat in stats[:top]:
        log.debug("  %s", stat)


def log_object_counts(label: str, *, top: int = 30, collect: bool = True) -> None:
    """Log the most common live object types, for retention/leak detection.

    Call after an operation (and across repeated operations) to see which
    types keep growing. No-op when the option is disabled.

    Args:
        label: Context label for the log line.
        top: Number of most common types to log.
        collect: Run ``gc.collect()`` first so only genuinely retained
            objects are counted.
    """
    if not DebugOpt.MEMORY.enabled:
        return
    from collections import Counter

    if collect:
        gc.collect()
    counts = Counter(type(obj).__name__ for obj in gc.get_objects())
    log.debug("memprofile[%s]: top %d live object types:", label, top)
    for name, count in counts.most_common(top):
        log.debug("  %6d  %s", count, name)


def deep_getsizeof(obj, _seen: set | None = None) -> int:
    """Recursively estimate the retained size of an object in bytes.

    Follows dict/list/tuple/set/frozenset containers and ``__dict__`` /
    ``__slots__`` attributes, deduplicating by id so shared references are
    counted once. This is an estimate (it cannot see C-level buffers it does
    not know about) but is useful for comparing the relative cost of core data
    structures such as ``Metadata`` or ``File`` at scale.
    """
    if _seen is None:
        _seen = set()
    obj_id = id(obj)
    if obj_id in _seen:
        return 0
    _seen.add(obj_id)

    size = sys.getsizeof(obj)

    if isinstance(obj, (str, bytes, bytearray)):
        return size
    if isinstance(obj, dict):
        for key, value in obj.items():
            size += deep_getsizeof(key, _seen)
            size += deep_getsizeof(value, _seen)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            size += deep_getsizeof(item, _seen)

    obj_dict = getattr(obj, '__dict__', None)
    if obj_dict:
        size += deep_getsizeof(obj_dict, _seen)

    slots = getattr(obj, '__slots__', None)
    if slots:
        if isinstance(slots, str):
            slots = (slots,)
        for slot in slots:
            if hasattr(obj, slot):
                size += deep_getsizeof(getattr(obj, slot), _seen)

    return size


def log_deep_size(label: str, obj) -> int:
    """Log the estimated retained size of a single object. No-op when disabled.

    Returns the measured size (0 when disabled) so callers may aggregate.
    """
    if not DebugOpt.MEMORY.enabled:
        return 0
    size = deep_getsizeof(obj)
    log.debug("memprofile[%s]: deep size of %r = %s", label, type(obj).__name__, _format_bytes(size))
    return size


def _metadata_size(md, seen: set) -> int:
    """Deep size of a Metadata object, deduplicated against ``seen``."""
    if md is None:
        return 0
    return deep_getsizeof(md, seen)


def analyze_album_footprint(album, *, log_result: bool = True) -> dict[str, int]:
    """Walk a loaded Album's object graph and return a size breakdown in bytes.

    Attributes memory to the components that are candidates for reduction. The
    primary "kept but unused later" suspect is the raw MusicBrainz release
    node: after loading, Album moves it from ``_release_node`` to
    ``_release_node_cache`` (retained solely for session export), so the full
    JSON stays resident for the whole album lifetime even when the user never
    exports a session. This analyzer measures it under either name.

    This is the runtime counterpart to the headless harness: load an album
    with ``--debug-opts=memory`` and read the breakdown from the log.

    Empirical findings (see PICARD-2172/2530 investigation): the dominant
    understood cost is the three per-track ``Metadata`` copies
    (``metadata`` + ``orig_metadata`` + ``scripted_metadata``), together
    typically ~35-40% of album footprint. The raw release node
    (``_release_node_cache``) is ~10%. ``track_objects_other`` is mostly fixed
    per-instance QObject overhead (signals, IgnoreUpdatesContext, the
    per-item attribute sets) plus TrackArtist sub-objects, and is not readily
    reducible payload.

    Returns an empty dict when the MEMORY option is disabled (no-op).

    Args:
        album: A loaded ``picard.album.Album`` instance.
        log_result: When True, log the breakdown; set False to only get the
            dict back (e.g. for tests or aggregation).
    """
    if not DebugOpt.MEMORY.enabled:
        return {}

    # Shared id-set so shared objects (e.g. cover-art images referenced by
    # multiple tracks) are counted once, in the first component that reaches
    # them. Order matters: measure the suspected-waste components first.
    seen: set = set()
    breakdown: dict[str, int] = {}

    # 1. Raw MB release node. After loading, Album moves it from
    #    ``_release_node`` to ``_release_node_cache`` (kept for session export),
    #    so the raw JSON is retained under one name or the other for the whole
    #    album lifetime. Measure whichever is present.
    release_node = getattr(album, '_release_node', None)
    if release_node is None:
        release_node = getattr(album, '_release_node_cache', None)
    breakdown['release_node'] = deep_getsizeof(release_node, seen) if release_node is not None else 0

    # 2. Cached recordings map, per-medium metadata.
    breakdown['recordings_map'] = deep_getsizeof(getattr(album, '_recordings_map', {}), seen)
    breakdown['per_medium_metadata'] = deep_getsizeof(getattr(album, 'per_medium_metadata', {}), seen)

    # 3. Album-level metadata copies.
    breakdown['album_metadata'] = _metadata_size(getattr(album, 'metadata', None), seen)
    breakdown['album_orig_metadata'] = _metadata_size(getattr(album, 'orig_metadata', None), seen)

    # 4. Per-track breakdown. Picard keeps up to three metadata copies per
    #    track (metadata, orig_metadata, scripted_metadata) plus track-artist
    #    objects and any remaining state. Measure metadata first so the
    #    catch-all remainder does not absorb it (dedup via ``seen``).
    tracks = getattr(album, 'tracks', []) or []
    track_meta = 0
    track_orig = 0
    track_scripted = 0
    track_artists = 0
    track_genres = 0
    track_remainder = 0
    for track in tracks:
        track_meta += _metadata_size(getattr(track, 'metadata', None), seen)
        track_orig += _metadata_size(getattr(track, 'orig_metadata', None), seen)
        track_scripted += _metadata_size(getattr(track, 'scripted_metadata', None), seen)
        track_artists += deep_getsizeof(getattr(track, '_track_artists', None), seen)
        # Genre / folksonomy tag Counters accumulated from the release data.
        track_genres += deep_getsizeof(getattr(track, '_genres', None), seen)
        track_genres += deep_getsizeof(getattr(track, '_folksonomy_tags', None), seen)
        # True remainder: the Track object and anything else it references that
        # was not already counted above (Qt QObject overhead, errors,
        # match_regexes, image dicts, files, etc.).
        track_remainder += deep_getsizeof(track, seen)
    breakdown['track_metadata'] = track_meta
    breakdown['track_orig_metadata'] = track_orig
    breakdown['track_scripted_metadata'] = track_scripted
    breakdown['track_artists'] = track_artists
    breakdown['track_genres_folksonomy'] = track_genres
    breakdown['track_objects_other'] = track_remainder

    breakdown['track_count'] = len(tracks)
    breakdown['total'] = sum(v for k, v in breakdown.items() if k != 'track_count')

    if log_result:
        album_name = None
        try:
            album_name = album.metadata['album']
        except Exception:
            album_name = getattr(album, 'id', '?')
        log.debug("memprofile[album]: footprint of %r (%d tracks):", album_name, breakdown['track_count'])
        for key in (
            'release_node',
            'recordings_map',
            'per_medium_metadata',
            'album_metadata',
            'album_orig_metadata',
            'track_metadata',
            'track_orig_metadata',
            'track_scripted_metadata',
            'track_artists',
            'track_genres_folksonomy',
            'track_objects_other',
        ):
            size = breakdown[key]
            pct = (100.0 * size / breakdown['total']) if breakdown['total'] else 0.0
            log.debug("  %-26s %12s  (%4.1f%%)", key, _format_bytes(size), pct)
        log.debug("  %-26s %12s", 'TOTAL', _format_bytes(breakdown['total']))

    return breakdown


def _count_metadata_objects(obj, seen: set) -> tuple[int, int]:
    """Return (metadata_object_count, total_bytes) reachable from obj.

    Counts distinct Metadata instances and their deep size, deduplicating via
    ``seen``. Used to attribute the dominant cost at scale: the raw number of
    Metadata dicts across the whole session.
    """
    # Local import to avoid a hard dependency / potential import cycle.
    from picard.metadata import Metadata

    count = 0
    total = 0
    for attr in ('metadata', 'orig_metadata', 'scripted_metadata'):
        md = getattr(obj, attr, None)
        if isinstance(md, Metadata) and id(md) not in seen:
            count += 1
            total += deep_getsizeof(md, seen)
    return count, total


def analyze_session_footprint(tagger, *, log_result: bool = True) -> dict[str, int]:
    """Walk the whole Tagger session and report an aggregate memory breakdown.

    This is the right granularity for the reported cases (whole collections:
    hundreds of albums, thousands of files/tracks). It aggregates across
    ``tagger.albums``, ``tagger.files`` and clusters, and reports totals plus
    per-item averages so scaling can be reasoned about.

    Key facts established during the audit, reflected in what this measures:
      - Cover art binary data is NOT held in RAM: it lives in temp files and is
        content-deduplicated via a hash-keyed WeakValueDictionary
        (picard.coverart.image.DataHash). So it is deliberately excluded here;
        the in-memory image objects are tiny (hash + filename).
      - The dominant RAM cost at scale is the sheer count of Metadata objects:
        2 per file (metadata, orig_metadata) and 3 per track (plus
        scripted_metadata). This function counts them explicitly.

    Measured evidence (31 albums, ~600 tracks, ~583 files loaded in one
    session, minimal-to-normal tags):
      - Metadata storage scales LINEARLY at ~8.5 KiB per Metadata object
        (~18-21 KiB per file+track). No super-linear storage blowup was seen;
        the multi-GB reports (PICARD-2172) are object-COUNT driven -- e.g.
        ~50k tracks projects to ~1.5-2 GB in Metadata alone, before Qt
        overhead.
      - retained release nodes grew to ~9.7 MiB for 31 albums (~313 KiB per
        album) and are NEVER freed: Album stores the full raw MB JSON in
        ``_release_node_cache`` at load and it is read only by
        session_exporter._export_mb_cache when the user exports a session.
        This is pure waste for users who never export -- a prime reduction
        target that scales with album count.

    Returns an empty dict when the MEMORY option is disabled (no-op).

    Args:
        tagger: The Tagger instance (has .albums dict and .files dict).
        log_result: When True, log the breakdown.
    """
    if not DebugOpt.MEMORY.enabled:
        return {}

    seen: set = set()
    stats: dict[str, int] = {}

    albums = list(getattr(tagger, 'albums', {}).values())
    files = list(getattr(tagger, 'files', {}).values())

    stats['album_count'] = len(albums)
    stats['file_count'] = len(files)

    # Total track count and Metadata-object accounting.
    track_count = 0
    metadata_obj_count = 0
    metadata_bytes = 0
    release_node_bytes = 0

    for album in albums:
        tracks = getattr(album, 'tracks', []) or []
        track_count += len(tracks)
        # Retained raw release node (either attribute name).
        node = getattr(album, '_release_node', None)
        if node is None:
            node = getattr(album, '_release_node_cache', None)
        if node is not None:
            release_node_bytes += deep_getsizeof(node, seen)
        c, b = _count_metadata_objects(album, seen)
        metadata_obj_count += c
        metadata_bytes += b
        for track in tracks:
            c, b = _count_metadata_objects(track, seen)
            metadata_obj_count += c
            metadata_bytes += b

    # File side: each loaded file holds metadata + orig_metadata.
    file_metadata_bytes = 0
    for f in files:
        c, b = _count_metadata_objects(f, seen)
        metadata_obj_count += c
        file_metadata_bytes += b
    metadata_bytes += file_metadata_bytes

    stats['track_count'] = track_count
    stats['metadata_object_count'] = metadata_obj_count
    stats['metadata_bytes'] = metadata_bytes
    stats['file_metadata_bytes'] = file_metadata_bytes
    stats['release_node_bytes'] = release_node_bytes

    if log_result:
        log.debug(
            "memprofile[session]: %d albums, %d tracks, %d files",
            stats['album_count'],
            stats['track_count'],
            stats['file_count'],
        )
        log.debug(
            "  Metadata objects: %d  totaling %s",
            stats['metadata_object_count'],
            _format_bytes(stats['metadata_bytes']),
        )
        if metadata_obj_count:
            log.debug("  avg per Metadata object: %s", _format_bytes(metadata_bytes / metadata_obj_count))
        log.debug("  file-side metadata: %s", _format_bytes(stats['file_metadata_bytes']))
        log.debug("  retained release nodes: %s", _format_bytes(stats['release_node_bytes']))
        items = stats['file_count'] + stats['track_count']
        if items:
            log.debug("  metadata bytes per file+track: %s", _format_bytes(metadata_bytes / items))

    return stats


# Timestamp of the last session summary, to throttle it during bulk loads.
_last_session_summary: float = 0.0


def log_session_footprint_throttled(tagger, *, min_interval: float = 5.0) -> None:
    """Log a session-wide footprint summary, at most once per ``min_interval``.

    Safe to call repeatedly from the main thread (e.g. after each album loads)
    during a large collection load: it will only emit a summary occasionally so
    the running total is visible without O(N^2) work on every album.

    Must be called from the main thread (it walks Qt model objects). No-op when
    the MEMORY option is disabled.
    """
    if not DebugOpt.MEMORY.enabled:
        return
    global _last_session_summary
    now = time.perf_counter()
    if now - _last_session_summary < min_interval:
        return
    _last_session_summary = now
    analyze_session_footprint(tagger)


class MemorySampler:
    """Background thread sampling process memory over time.

    Produces a memory-over-time curve without any external profiler. Uses
    ``tracemalloc`` for Python-traced memory and, when available, ``psutil`` or
    :func:`resource.getrusage` for process RSS. Does nothing when the MEMORY
    option is disabled.
    """

    def __init__(self, interval: float = 0.5, label: str = "sampler"):
        self.interval = interval
        self.label = label
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def _rss_bytes(self) -> int | None:
        """Best-effort resident set size in bytes, or None if unavailable."""
        try:
            import psutil  # ty: ignore[unresolved-import]  # optional dependency

            return psutil.Process().memory_info().rss
        except ImportError:
            pass
        try:
            import resource

            usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # Linux reports KiB, macOS reports bytes.
            if sys.platform == 'darwin':
                return usage
            return usage * 1024
        except (ImportError, ValueError):
            return None

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            traced = None
            if tracemalloc.is_tracing():
                current, peak = tracemalloc.get_traced_memory()
                traced = f"traced={_format_bytes(current)} peak={_format_bytes(peak)}"
            rss = self._rss_bytes()
            rss_str = _format_bytes(rss) if rss is not None else "n/a"
            log.debug("memprofile[%s]: rss=%s %s", self.label, rss_str, traced or "")

    def start(self) -> None:
        if not DebugOpt.MEMORY.enabled:
            return
        ensure_tracing()
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="MemorySampler", daemon=True)
        self._thread.start()
        log.debug("memprofile[%s]: sampler started (interval=%.2fs)", self.label, self.interval)

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join(timeout=self.interval * 2)
        self._thread = None
        log.debug("memprofile[%s]: sampler stopped", self.label)

    def __enter__(self) -> 'MemorySampler':
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
