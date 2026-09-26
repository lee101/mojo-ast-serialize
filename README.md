# mojo-ast-serialize

`mojo-ast-serialize` is the byte-level part of
[ast_serialize](https://pypi.org/project/ast-serialize/): the source hash it
computes on every parse, and the `# type: ignore[...]` scan it runs over the
source. Both are implemented as Mojo kernels behind a C ABI.

The Python package is named `mojo_ast_serialize`, so it installs alongside the
real `ast_serialize` and never shadows it.

```python
import ast_serialize
import mojo_ast_serialize as mas

src = b"x = 1  # type: ignore[assignment]\n"
mas.source_hash(src).hex()   # == ast_serialize.parse("m.py", src)[4]["source_hash"]
mas.type_ignores(src)        # == ast_serialize.parse("m.py", src)[2]
```

## What was ported, and why

`ast_serialize` is a compiled Rust extension (a `rustpython-ast` based parser
that serialises the AST to bytes). Its numeric core is not the parser: the
parser is recursion over a grammar. The two things it does that *are* byte-level
loops over the whole source file, and that it exposes in its result, are:

* `source_hash` — the SHA-1 of the source bytes, which is the key it caches the
  serialised AST under. Verified to be exactly `hashlib.sha1` of the input
  bytes (UTF-8 encoded when a `str` is passed), including the BOM and CRLF
  cases.
* `mypy_ignores` — the list of `(line, [code, ...])` pairs found in
  `# type: ignore[...]` comments. Producing it requires lexing enough of Python
  to know which `#` characters begin a comment and which sit inside a string
  literal, which is a real scanner over every byte of the source.

Both are ported. The grammar of the type-ignore comment was reverse-engineered
from the upstream implementation and is documented in the kernel docstring; the
parity tests pin every form, accepted and rejected.

## Covered subset

| area | implemented API |
| --- | --- |
| Source hash | `mojo_ast_serialize.source_hash(source) -> bytes`, the 20-byte SHA-1 |
| Comment lexer | `mojo_ast_serialize.comments(source, cap) -> [(offset, length, line)]` |
| Type-ignore grammar | `mojo_ast_serialize.match_type_ignore(comment) -> list[str] | None` |
| Full ignore scan | `mojo_ast_serialize.type_ignores(source, cap) -> [(line, [code, ...])]` |
| Kernels | `astsha1`, `ast_comments`, `ast_match_type_ignore` |

## Not implemented

* **The parser and the serialised AST.** `parse` and `parse_type_string` return
  a serialised AST as `bytes` in an undocumented binary format. Reimplementing
  a Python grammar and its serialiser is a port of the whole package, not of a
  numeric core, and the format is not specified anywhere, so reverse-engineering
  it would be guesswork. Forward to the real `ast_serialize`.
* **`mypy_comments`.** The third field of `_ASTData` is documented as
  `list[tuple[int, str]]`, but it is empty for every input tried here: plain
  type comments, function-signature type comments, `# type: List[int]`,
  `# type: int` on assignments, annotated and unannotated, at several
  `python_version` settings. It appears to be unpopulated in this build, so
  there is nothing to port and nothing to test.
* **Unicode alphanumerics in error codes.** Upstream accepts a code made of
  Unicode alphanumerics (`# type: ignore[αβ]` yields `['αβ']`). This port
  restricts a code to ASCII alphanumerics plus `_` and `-`, which is the shape
  of a real mypy error code. Unicode *whitespace* around and inside the code
  list is fully supported, and non-alphanumeric Unicode inside a code is
  correctly rejected, as upstream does. `test_type_ignore_grammar_matches_upstream`
  asserts parity on every ASCII form; the Unicode-alphanumeric divergence is
  the one known difference and is called out here rather than hidden.
* **Syntax errors.** `ast_serialize.parse` reports `ParseError` entries with a
  line and column for invalid source. Nothing in this port parses, so it has
  no error reporting.
* **Caching.** The on-disk AST cache keyed by `source_hash` is upstream's own
  concern and stays there; only the key is ported.

## Install and build

```bash
bash build/build.sh          # -> dist/libmojo-ast-serialize.so
PYTHONPATH=python python -m pytest tests -q
```

`build/build.sh` compiles the single compilation unit `src/kernels.mojo` with
`mojo build --emit shared-lib`. Buffers cross the C ABI as 64-bit addresses and
are rebuilt as `Pointer[UInt8, AnyOrigin[mut=True]]` inside each kernel. The
library owns no memory: the SHA-1 message schedule is a caller-supplied
320-byte scratch buffer, because the library holds no state of its own.

## Tests

89 tests, all passing, all exact. Both ported functions are compared against the
real `ast_serialize`: `source_hash` against the `source_hash` field of
`parse(...)`, and the ignore list against `parse(...)[2]`. The coverage is:

* SHA-1 against `hashlib` for every length from 0 to 79 and at 119, 120, 127,
  128, 200, 1000 and 4096 bytes, so every padding and block boundary is
  exercised; and against upstream on BOM, CRLF, empty and non-UTF-8-adjacent
  inputs.
* The comment lexer against its own contract: a `#` in a `str` literal, in a
  triple-quoted string, and in a raw string with an escaped quote are not
  comments; an unterminated string ends the scan.
* Every accepted and rejected spelling of the type-ignore grammar, each checked
  against both the hand-written expectation and upstream.
* Whole-file parity on the first 40 UTF-8 modules in the test environment's
  `site-packages`, and on a synthetic source containing every escape shape.

## Performance

Best-of-five wall clock on one megabyte of source, against the strongest
available baseline for each case. Every case verifies agreement first.

| case | reference | mojo-ast-serialize | result |
| --- | ---: | ---: | ---: |
| SHA-1, n=1048576 | 2.60 ms | 16.50 ms | **0.16x, a 6.2x loss** |
| comment lexer, n=1048576 | 410.83 ms | 23.26 ms | 17.66x faster |
| `mypy_ignores`, n=1048576 | 419.61 ms | 51.24 ms | 8.19x faster |

The SHA-1 loss is real and is reported as one. `hashlib` dispatches to
OpenSSL's hand-written SHA-1 assembly with SHA-NI hardware acceleration where
available; a portable C loop is not going to beat that, and this kernel is a
straightforward FIPS 180-4 transcription. The reason it is ported anyway is
that it is the right shape for the rest of the byte-level work: it is a real
kernel that runs correctly on every input, and it removes a dependency on
`hashlib` being hardware-accelerated. On a machine without SHA-NI the gap would
be far smaller.

The two scans win because the Python alternative is `tokenize`, a pure-Python
generator that materialises a `TokenInfo` namedtuple per token, and a regex per
comment.

Reproduce with:

```bash
python bench/bench.py
```

## How it works

`ast_comments` is a byte scanner with two states: outside a string, where `#`
opens a comment that runs to the end of the line; and inside a string, where
escapes are always honoured, triple quotes are tracked, and newlines are
counted so that line numbers stay physical. That second point matters: a `#` in
a multi-line string must not be reported, and the line number of every later
comment must still be right.

`ast_match_type_ignore` then applies the grammar to each comment span. It is
exported separately so the grammar can be tested without the lexer.

## License

MIT, per this repository's `LICENSE`. Upstream `ast_serialize` is MIT; no
upstream code is vendored here, only its observed behaviour.
