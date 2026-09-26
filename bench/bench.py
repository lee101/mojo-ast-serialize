"""Correctness-gated benchmark for mojo-ast-serialize.

Every case verifies exact agreement with the reference before timing, so a
regression in the Mojo kernels shows up as a correctness failure rather than a
suspiciously good number.

The SHA-1 baseline is `hashlib`, which is OpenSSL's assembly-optimised C
implementation. That is the strongest baseline available anywhere in this
process, so a loss here is a real loss and is reported as one.
"""

from __future__ import annotations

import hashlib
import io
import pathlib
import re
import sys
import time
import tokenize

import numpy as np

_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "python"))

import mojo_ast_serialize as mas  # noqa: E402

# One whole module, repeated. A cache key is one source file, and the
# tokenizer baseline needs the text to be a syntactically complete sequence, so
# the benchmark repeats a single valid module rather than concatenating a
# random selection.
_MODULE = (
    pathlib.Path(__file__).resolve().parent.parent / "bench" / "bench.py"
).read_bytes()
_BLOB = _MODULE * 8

_IGNORE_RE = re.compile(
    rb"^[ \t]*type:[ \t]*ignore(?:[ \t]*#|[ \t]*\[[A-Za-z0-9_,-]*\][ \t]*)?$"
)


def _time(fn, repeats=5):
    best = float("inf")
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def bench_sha1(n: int = 1 << 20):
    """SHA-1 of a megabyte of source: the cache key computed on every parse."""
    data = (_BLOB * (n // len(_BLOB) + 1))[:n]
    got = mas.source_hash(data)
    assert got == hashlib.sha1(data).digest(), "sha1 mismatch"
    assert len(got) == 20
    return f"sha1 n={n}", _time(lambda: hashlib.sha1(data).digest()), \
        _time(lambda: mas.source_hash(data))


def bench_comments(n: int = 1 << 20):
    """The comment lexer, against the standard library tokenizer."""
    data = (_BLOB * (n // len(_BLOB) + 1))[:n]
    text = data.decode("utf-8", "replace")
    mine = mas.comments(data, cap=1 << 16)
    theirs = [
        (tok.string, tok.start[0])
        for tok in tokenize.generate_tokens(io.StringIO(text).readline)
        if tok.type == tokenize.COMMENT
    ]
    # The same comments, in the same order, at the same lines. Offsets are
    # compared on the decoded text because the tokenizer indexes characters.
    assert [(text[o:o + ln], line) for o, ln, line in mine] == theirs, (
        len(mine), len(theirs)
    )

    def mojo():
        return mas.comments(data, cap=1 << 16)

    def stdlib():
        return [
            tok for tok in tokenize.generate_tokens(io.StringIO(text).readline)
            if tok.type == tokenize.COMMENT
        ]

    return f"comment lexer n={n}", _time(stdlib, 3), _time(mojo, 3)


def bench_type_ignores(n: int = 1 << 20):
    """The whole `mypy_ignores` pipeline: lex, then match each comment."""
    data = (_BLOB * (n // len(_BLOB) + 1))[:n]
    text = data.decode("utf-8", "replace")
    got = mas.type_ignores(data, cap=1 << 16)
    want = []
    line = 1
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type == tokenize.COMMENT and _IGNORE_RE.match(tok.string.encode()):
            body = tok.string[1:]
            codes = []
            m = re.search(rb"\[([A-Za-z0-9_,-]*)\]", body.encode())
            if m:
                codes = [c for c in m.group(1).decode().split(",") if c]
            want.append((tok.start[0], codes))
    assert got == want, (got[:5], want[:5])

    def mojo():
        return mas.type_ignores(data, cap=1 << 16)

    def numpy():
        out = []
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT and _IGNORE_RE.match(
                tok.string.encode()
            ):
                m = re.search(rb"\[([A-Za-z0-9_,-]*)\]", tok.string[1:].encode())
                out.append((tok.start[0], [
                    c for c in m.group(1).decode().split(",") if c
                ] if m else []))
        return out

    return f"mypy_ignores n={n}", _time(numpy, 3), _time(mojo, 3)


def main():
    print(f"{'case':<28}{'reference':>13}{'mojo-ast-serialize':>20}{'ratio':>9}")
    print("-" * 72)
    for fn in (bench_sha1, bench_comments, bench_type_ignores):
        label, ref, got = fn()
        ratio = ref / got if got else float("nan")
        print(f"{label:<28}{ref * 1e3:>11.2f}ms{got * 1e3:>18.2f}ms"
              f"{ratio:>8.2f}x")


if __name__ == "__main__":
    main()
