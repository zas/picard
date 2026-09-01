#!/usr/bin/env python3
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

"""Headless memory/CPU profiling harness for bulk metadata operations.

This measures the *data layer* cost of the operations implicated in
PICARD-2172 (memory) and PICARD-2530 (CPU): building large collections of
File/Metadata objects and applying "use original values" style bulk mutations.
It deliberately avoids the Qt GUI so it can run anywhere, giving a repeatable
baseline to evaluate the impact of later changes.

The point is to MEASURE BEFORE CHANGING. Run this at several sizes and compare
the growth curve (linear vs super-linear) and the top allocating source lines.

Scope and caveats:
  - This profiles the DATA LAYER only (File/Metadata construction and tag
    mutation). It uses a mocked Tagger, so allocations attributed to
    ``unittest.mock`` in the output are harness artifacts, not Picard cost;
    ignore them.
  - It deliberately does NOT exercise the Qt UI update fan-out
    (Album.update -> tree items -> repaint), which is the most likely source
    of the runaway cost reported in PICARD-2172/2530. To measure that,
    reproduce the operation in a running GUI with ``--debug-opts=memory`` and
    read the ``memprofile[...]`` log lines emitted around
    ``_apply_update_funcs`` / ``_remove_tags``.
  If the data layer here scales linearly but the GUI does not, the problem is
  in the UI layer, and this harness has done its job by ruling out the data
  layer.

Usage:

    python scripts/profile_bulk_metadata.py --sizes 100,1000,5000
    python scripts/profile_bulk_metadata.py --sizes 1000 --tracemalloc-top 40
"""

import argparse
import cProfile
import gc
import io
from pathlib import Path
import pstats
import sys
import tracemalloc


# Allow running from a source checkout without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _fmt(num: float) -> str:
    for unit in ('B', 'KiB', 'MiB', 'GiB'):
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TiB"


def _install_mock_environment():
    """Install a minimal mocked Tagger + config so File objects can be built
    without a running Qt application.

    Reuses the same mocking approach as the test suite (see
    test/picardtestcase.py) but standalone, so the harness can run headless.
    """
    from unittest.mock import MagicMock

    from picard import config
    import picard.item

    fake_config = MagicMock()
    fake_config.setting = {'save_acoustid_fingerprints': False}
    fake_config.persist = {}
    fake_config.profiles = {}
    config.config = fake_config
    config.setting = fake_config.setting
    config.persist = fake_config.persist
    config.profiles = fake_config.profiles

    tagger = MagicMock()
    tagger.stopping = False
    tagger.files = {}
    tagger.acoustidmanager = MagicMock()
    # File.tagger property calls tagger_instance(); patch it in picard.item.
    picard.item.tagger_instance = lambda: tagger
    return tagger


def build_files(n: int):
    """Build N synthetic File objects with both metadata and orig_metadata.

    Mirrors the loaded-file state: orig_metadata holds the on-disk values and
    metadata holds edited values, which is the situation "use original values"
    operates on.
    """
    from picard.file import File
    from picard.metadata import Metadata

    files = []
    for i in range(n):
        f = File(f'/music/artist/album/{i:05d}.flac')
        orig = Metadata()
        orig['title'] = f'Original Title {i}'
        orig['artist'] = ['Artist A', 'Artist B']
        orig['album'] = 'Some Album Name'
        orig['tracknumber'] = str(i)
        orig['genre'] = ['Rock', 'Alternative', 'Indie']
        orig['comment'] = 'A moderately long comment field ' * 4
        f.orig_metadata = orig
        f.metadata.copy(orig)
        # Simulate an edit so "use original values" has work to do.
        f.metadata['title'] = f'Edited Title {i}'
        files.append(f)
    return files


def bulk_use_original(files, tag: str = 'title'):
    """Replicate the per-object mutation done by _use_orig_tags for a tag.

    This is the data-layer core of the "Use Original Values" action, minus the
    Qt UI updates. It is what runs once per selected object.
    """
    for f in files:
        orig_values = list(f.orig_metadata.getall(tag)) or [""]
        if orig_values == [""]:
            del f.metadata[tag]
        else:
            f.metadata[tag] = orig_values


def profile_size(n: int, tracemalloc_top: int, do_cprofile: bool):
    print(f"\n{'=' * 70}\nWorkload size N = {n}\n{'=' * 70}")

    gc.collect()
    tracemalloc.start(25)

    snap0 = tracemalloc.take_snapshot()
    files = build_files(n)
    snap1 = tracemalloc.take_snapshot()

    build_current, build_peak = tracemalloc.get_traced_memory()
    print(f"\n[build] traced current={_fmt(build_current)} peak={_fmt(build_peak)}")
    print(f"[build] per-file ≈ {_fmt(build_current / n)}")

    print(f"\n[build] top {tracemalloc_top} allocating lines:")
    for stat in snap1.compare_to(snap0, 'lineno')[:tracemalloc_top]:
        print(f"  {stat}")

    # Measure the bulk mutation itself.
    snap2 = tracemalloc.take_snapshot()
    if do_cprofile:
        profiler = cProfile.Profile()
        profiler.enable()
        bulk_use_original(files)
        profiler.disable()
    else:
        bulk_use_original(files)
    snap3 = tracemalloc.take_snapshot()

    op_current, op_peak = tracemalloc.get_traced_memory()
    print(f"\n[use-original] traced current={_fmt(op_current)} peak={_fmt(op_peak)}")
    print(f"\n[use-original] top {tracemalloc_top} allocating lines:")
    for stat in snap3.compare_to(snap2, 'lineno')[:tracemalloc_top]:
        print(f"  {stat}")

    if do_cprofile:
        stream = io.StringIO()
        stats = pstats.Stats(profiler, stream=stream).sort_stats('cumulative')
        stats.print_stats(20)
        print(f"\n[use-original] cProfile (cumulative, top 20):\n{stream.getvalue()}")

    # Retention check: drop references and see what survives.
    del files
    gc.collect()
    from collections import Counter

    counts = Counter(type(o).__name__ for o in gc.get_objects())
    interesting = ('Metadata', 'File', 'ImageList', 'list', 'dict')
    print("[retention] live objects of interest after gc.collect():")
    for name in interesting:
        print(f"  {counts.get(name, 0):8d}  {name}")

    tracemalloc.stop()
    return build_current / n


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--sizes', default='100,1000,5000', help="Comma-separated workload sizes")
    parser.add_argument('--tracemalloc-top', type=int, default=20, help="Top allocating lines to show")
    parser.add_argument('--no-cprofile', action='store_true', help="Skip cProfile CPU measurement")
    args = parser.parse_args()

    sizes = [int(s) for s in args.sizes.split(',') if s.strip()]
    _install_mock_environment()
    per_file = {}
    for n in sizes:
        per_file[n] = profile_size(n, args.tracemalloc_top, not args.no_cprofile)

    if len(per_file) > 1:
        print(f"\n{'=' * 70}\nPer-file build cost across sizes (should be ~constant if linear)\n{'=' * 70}")
        for n, cost in per_file.items():
            print(f"  N={n:6d}  {_fmt(cost)}/file")


if __name__ == '__main__':
    main()
