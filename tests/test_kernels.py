"""Parity tests for mojo-ast-serialize against the real `ast_serialize`.

The real package is a compiled Rust extension and is installed in the test
environment, so both functions ported here are compared against it directly:
`source_hash` against the `source_hash` field of `ast_serialize.parse`, and the
comment scan against its `mypy_ignores` result.

Both are exact integer and byte operations, so the comparisons are exact
(`==`, `assert ... ==`) with no tolerance. That is the point of porting them:
SHA-1 and a grammar matcher over bytes have one right answer.
"""

import ast
import hashlib
import pathlib

import numpy as np
import pytest

import ast_serialize as upstream

import mojo_ast_serialize as mas

pytestmark = pytest.mark.skipif(
    upstream is None, reason="ast_serialize is not installed"
)

def _utf8_files():
    out = []
    for p in sorted(pathlib.Path(upstream.__file__).parent.parent.glob("*.py")):
        try:
            p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        out.append(p)
    return out


FILES = _utf8_files()


def upstream_ignores(src: bytes):
    return upstream.parse("probe.py", src)[2]


def upstream_hash(src: bytes) -> str:
    return upstream.parse("probe.py", src)[4]["source_hash"]


# ---------------------------------------------------------------- SHA-1


def test_source_hash_matches_the_upstream_cache_key():
    for src in (b"", b"x = 1\n", b"x = 1\r\n", b"\xef\xbb\xbfx = 1\n",
                b"no trailing newline", b"y" * 200,
                "# type: ignore\n" * 37, "caf\u00e9 \u2603\n".encode()):
        assert mas.source_hash(src).hex() == upstream_hash(src), src[:20]


def test_source_hash_matches_hashlib():
    """hashlib is the independent oracle for FIPS 180-4 SHA-1."""
    rng = np.random.default_rng(0)
    for size in (0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 1000):
        data = bytes(rng.integers(0, 256, size, dtype=np.uint8))
        assert mas.source_hash(data) == hashlib.sha1(data).digest(), size


def test_source_hash_covers_every_block_boundary():
    """A padding bug shows up only at the lengths where the extra block is
    needed, so walk the 55/56/57 and 119/120/121 boundaries explicitly."""
    data = b"a" * 300
    for size in range(0, 300):
        chunk = data[:size]
        assert mas.source_hash(chunk) == hashlib.sha1(chunk).digest(), size


def test_source_hash_accepts_text_and_encodes_utf8():
    text = "x = 'ééé'  # café\n"
    assert mas.source_hash(text) == hashlib.sha1(
        text.encode("utf-8")
    ).digest()
    assert mas.source_hash(text) == bytes.fromhex(upstream_hash(
        text.encode("utf-8")
    ))


def test_source_hash_is_sensitive_to_a_single_bit():
    a = mas.source_hash(b"x = 1\n")
    b = mas.source_hash(b"x = 2\n")
    assert a != b
    assert len(set(a)) > 10


# ------------------------------------------------------- comment lexer


def test_comment_lexer_finds_real_comments_only():
    src = b'''x = 1  # one
y = "# not a comment"
z = """
# also not
"""
w = 2  # two
'''
    found = mas.comments(src)
    assert [(src[o:o + n], line) for o, n, line in found] == [
        (b"# one", 1), (b"# two", 6),
    ]


def test_comment_lexer_counts_lines_through_triple_quoted_strings():
    src = b'x = """\n\n# not a comment\n"""\ny = 1  # yes\n'
    found = mas.comments(src)
    assert [(src[o:o + n], line) for o, n, line in found] == [(b"# yes", 5)]


def test_comment_lexer_honours_escapes_in_raw_prefixed_strings():
    """`r"\\""` is an unterminated raw string as far as the upstream tokenizer
    is concerned, so the `#` after it is string content, not a comment."""
    src = b'x = r"\\"# not a comment"\ny = 1  # yes\n'
    assert [(src[o:o + n], line) for o, n, line in mas.comments(src)] == [
        (b"# yes", 2),
    ]


def test_comment_lexer_reports_an_unterminated_string_as_end_of_input():
    src = b'x = "unterminated\n# this is not a comment\n'
    assert mas.comments(src) == []


def test_comment_lexer_matches_upstream_comment_positions():
    """The offsets and line numbers must line up with what the upstream parser
    sees, which is observable through the `mypy_ignores` it reports."""
    for src in (
        b"x = 1  # type: ignore\n",
        b"a = 1\n# type: ignore\nb = 2\n# type: ignore[misc]\n",
        b'x = """\n# type: ignore\n"""\n# type: ignore\n',
        b"x = 1  # type: ignore\r\ny = 2  # type: ignore[misc]\r\n",
        b"x = 1  + \\\n  2  # type: ignore\n",
    ):
        ours = mas.type_ignores(src)
        assert ours == upstream_ignores(src), src


# --------------------------------------------- the type-ignore grammar


@pytest.mark.parametrize("src,expect", [
    (b"x = 1  # type: ignore\n", [(1, [])]),
    (b"x = 1  # type: ignore[misc]\n", [(1, ["misc"])]),
    (b"x = 1  # type: ignore[assignment, misc]\n",
     [(1, ["assignment", "misc"])]),
    (b"x = 1  # type: ignore [a, b , c]\n", [(1, ["a", "b", "c"])]),
    (b"x = 1  # type: ignore[a,,b]\n", [(1, ["a", "b"])]),
    (b"x = 1  # type: ignore[]\n", [(1, [])]),
    (b"x = 1  #type:ignore\n", [(1, [])]),
    (b"x = 1  #  type:  ignore\n", [(1, [])]),
    (b"x = 1\t# type:\tignore\n", [(1, [])]),
    (b"x = 1  # type: ignore \n", [(1, [])]),
    (b"x = 1  # type: ignore # trailing\n", [(1, [])]),
    (b"x = 1  # type: ignore [x]\n", [(1, ["x"])]),
    (b"x = 1  # type: ignore[a-b]\n", [(1, ["a-b"])]),
    (b"x = 1  # type: ignore[1]\n", [(1, ["1"])]),
    (b"x = 1  # type: ignore[_]\n", [(1, ["_"])]),
    (b"x = 1  # type: ignore[A_b1]\n", [(1, ["A_b1"])]),
    # Rejected forms.
    (b"x = 1  # type : ignore\n", []),
    (b"x = 1  # type: ignorex\n", []),
    (b"x = 1  # type: ignore_\n", []),
    (b"x = 1  # type: IGNORE\n", []),
    (b"x = 1  # noqa  # type: ignore\n", []),
    (b"x = 1  #  # type: ignore\n", []),
    (b"x = 1  # type:\n", []),
    (b"x = 1  #\n", []),
    (b"x = 1  # type: ignore[a\n", []),
    (b"x = 1  # type: ignore[a]xyz\n", []),
    (b"x = 1  # type: ignore a]\n", []),
    (b"x = 1  # type: ignore[a b]\n", []),
    (b"x = 1  # type: ignore['a']\n", []),
    (b"x = 1  # type: ignore[a.b]\n", []),
    (b"x = 1  # type: ignore[a;b]\n", []),
    (b"x = 1  # type: ignore[a=b]\n", []),
    (b"x = 1  # type: ignore[a\\x01b]\n", []),
    # Strings are not comments.
    (b'x = "# type: ignore"\n', []),
    (b'x = """\n# type: ignore\n"""\n', []),
])
def test_type_ignore_grammar_matches_upstream(src, expect):
    assert mas.type_ignores(src) == expect
    assert mas.type_ignores(src) == upstream_ignores(src)


def test_type_ignore_line_numbers_are_physical():
    src = b"a = 1\n\n\nb = 2  # type: ignore[one]\nc = 3\nd = 4  # type: ignore\n"
    assert mas.type_ignores(src) == [(4, ["one"]), (6, [])]
    assert mas.type_ignores(src) == upstream_ignores(src)


def test_type_ignore_codes_are_exact_bytes():
    src = b"x = 1  # type: ignore[LongCode_NAME-2]\n"
    (line, codes), = mas.type_ignores(src)
    assert line == 1
    assert codes == ["LongCode_NAME-2"]


def test_unicode_space_separators_match_upstream():
    """The upstream tokenizer treats U+00A0 as whitespace around the codes, and
    the port does too, including the multi-byte forms."""
    for src in (
        "# type: ignore[\u00a0a\u00a0]\n".encode(),
        "# type: ignore[a\u00a0b]\n".encode(),
        "# type:\u00a0ignore\n".encode(),
        "#\u2003type: ignore\n".encode(),
        "# type: ignore[a\u2014b]\n".encode(),
        "# type: ignore[a\u3000b]\n".encode(),
    ):
        assert mas.type_ignores(src) == upstream_ignores(src), src


def test_unicode_alphanumeric_codes_are_the_one_documented_divergence():
    """Upstream accepts a code made of Unicode alphanumerics; this port
    restricts codes to ASCII. Pinned here so the difference is visible rather
    than latent."""
    src = "# type: ignore[\u03b1\u03b2]\n".encode()
    assert upstream_ignores(src) == [(1, ["\u03b1\u03b2"])]
    assert mas.type_ignores(src) == []
    # Non-alphanumeric Unicode is rejected by both, as it should be.
    src = "# type: ignore[a\u2014b]\n".encode()
    assert mas.type_ignores(src) == upstream_ignores(src) == []


# ------------------------------------------------------ whole-file parity


@pytest.mark.parametrize("path", FILES[:40], ids=lambda p: p.name)
def test_whole_file_parity(path):
    """On real modules: the hash and the ignore list must both agree."""
    src = path.read_bytes()
    assert mas.source_hash(src).hex() == upstream_hash(src)
    assert mas.type_ignores(src) == upstream_ignores(src)


def test_parity_on_source_with_every_escape_shape():
    src = b"\n".join([
        b"import os  # type: ignore[import-untyped]",
        b"x = 1  # type:ignore",
        b"y = '\\'# not a comment'  # type: ignore[a]",
        b"z = '''",
        b"# type: ignore",
        b"'''  # type: ignore[b]",
        b"w = f'{x!r}#y'  # type: ignore",
        b"v = 1  # noqa  # type: ignore",
        b"u = 2  # type: ignore[c] extra",
    ]) + b"\n"
    assert mas.type_ignores(src) == upstream_ignores(src)
    ast.parse(src.decode())  # the source is valid Python
