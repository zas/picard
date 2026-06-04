# String Similarity: `astrcmp` Implementations

## Overview

Picard uses an approximate string comparison function (`astrcmp`) for matching
file metadata against MusicBrainz data. It is called from `picard/similarity.py`
and is critical for file-to-track matching and clustering.

The function returns a similarity score between 0.0 (completely different) and
1.0 (identical).

## Algorithm

Despite its name suggesting simple Levenshtein distance, the C implementation
(`_astrcmp.c`) actually implements **Optimal String Alignment (OSA)** distance,
which extends Levenshtein with adjacent transposition detection. This means
swapping two neighboring characters (e.g., "teh" → "the") costs 1 edit instead
of 2.

The formula is: `1.0 - osa_distance(a, b) / max(len(a), len(b))`

## Implementations

Three backends are available, selected automatically in priority order:

| Priority | Backend | Source | Algorithm |
|----------|---------|--------|-----------|
| 1 | rapidfuzz | `rapidfuzz.distance.OSA` | Optimal String Alignment |
| 2 | C extension | `picard/util/_astrcmp.c` | OSA (with boundary bug) |
| 3 | Pure Python | `picard/util/astrcmp.py:astrcmp_py` | Levenshtein only |

The active implementation is exposed as `astrcmp_implementation` (one of
`"rapidfuzz"`, `"C"`, or `"Python"`), displayed in Help → About.

## Performance

Measured on Linux x86_64, Python 3.12, 500,000 calls per category:

| String length | C extension | rapidfuzz OSA | Speedup |
|---------------|-------------|---------------|---------|
| Short (3–8 chars) | 3.8M calls/s | 3.3M calls/s | 0.9x (comparable) |
| Medium (15–30 chars) | 607K calls/s | 2.8M calls/s | **4.5x faster** |
| Long (80–200 chars) | 19.5K calls/s | 424K calls/s | **21.7x faster** |

The pure Python fallback is ~64–84x slower than the C extension.

For typical music metadata (artist names, track titles: 10–50 characters),
rapidfuzz is approximately **6x faster** than the C extension.

## Equivalence

Testing 50,000 random string pairs (lengths 1–100):

- Maximum difference between rapidfuzz and C: **3.97×10⁻⁸** (float32 vs float64)
- Cases with difference > 0.001: **0**
- Cases with any measurable difference: **0** (beyond float precision)

The implementations are functionally equivalent for all practical inputs.

## Detected Issues in `_astrcmp.c`

### 1. Transposition boundary bug

The C code guards the transposition step with:

```c
if (index1 > 2 && index2 > 2)
```

This disables transposition detection for the first 2 character positions of
either string. The correct OSA algorithm has no such restriction. As a result:

| Input | C result | Correct (OSA) | Impact |
|-------|----------|---------------|--------|
| `"ab"` vs `"ba"` | 0.0 | 0.5 | C misses the swap |
| `"abc"` vs `"bac"` | 0.33 | 0.67 | C misses the swap |
| `"abcd"` vs `"bacd"` | 0.5 | 0.75 | C misses the swap |
| `"xab"` vs `"xba"` | 0.67 | 0.67 | ✓ (position > 2) |

This bug has no practical impact for music metadata, as strings are typically
longer and transpositions in the first 2 characters of both strings simultaneously
are extremely rare in real-world queries.

### 2. Float32 precision

The C code uses `float` (32-bit) for the final division, while rapidfuzz uses
`double` (64-bit). This causes differences up to ~4×10⁻⁸, which is completely
negligible for similarity scoring.

### 3. Python fallback uses different algorithm

The pure Python fallback (`astrcmp_py`) implements standard Levenshtein distance
without transposition support. This means results differ from the C/rapidfuzz
implementations when adjacent character transpositions are present.

## Dependencies

| Backend | Dependency | License | Wheel size | Platforms |
|---------|-----------|---------|------------|-----------|
| rapidfuzz | `rapidfuzz>=3.0.0` | MIT | ~3 MB | All major (pre-built wheels) |
| C extension | C compiler at build time | GPL-2.0+ (Picard) | Built-in | Requires compilation |
| Pure Python | None | CC0 | Built-in | Universal |

## Pros & Cons

### rapidfuzz

**Pros:**
- 6–22x faster than C extension for typical to long strings
- Correct OSA implementation (no boundary bug)
- Pre-built wheels: no compiler needed for installation
- Well-maintained, actively developed (MIT license)
- Also provides other distance metrics if needed in the future

**Cons:**
- External dependency (~3 MB)
- Slight overhead for very short strings (< 8 chars) due to Python function call

### C extension (`_astrcmp.c`)

**Pros:**
- No external dependency (ships with Picard source)
- Fast for short strings

**Cons:**
- Requires C compiler to build from source
- Contains boundary bug in transposition detection
- Float32 precision loss
- Maintenance burden (custom code vs. well-tested library)
- Slower than rapidfuzz for medium/long strings

### Pure Python fallback

**Pros:**
- Zero dependencies, always available
- Simple, readable implementation

**Cons:**
- 64–84x slower than C extension
- Only implements Levenshtein (no transposition detection)
- Not suitable for large music collections

## Configuration

rapidfuzz is declared as an optional dependency in `pyproject.toml`:

```shell
uv sync --extra rapidfuzz
```

When not installed, the fallback chain (C → Python) activates automatically.
