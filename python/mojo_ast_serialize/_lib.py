"""ctypes bridge to the compiled Mojo kernels.

The shared library owns no memory. Every buffer crosses the C ABI as a 64-bit
address, so the argtypes below must stay `c_int64` for addresses; `c_int`
truncates them and segfaults.
"""

import ctypes
import pathlib

import numpy as np

_HERE = pathlib.Path(__file__).resolve()
_ROOT = _HERE.parents[2]
_LIB_PATH = _ROOT / "dist" / "libmojo-ast-serialize.so"

_I = ctypes.c_int64
_RET = ctypes.c_int64

_SIGNATURES = {
    "astsha1": [_I, _I, _I, _I],
    "ast_comments": [_I, _I, _I, _I, _I, _I],
    "ast_match_type_ignore": [_I, _I, _I, _I, _I, _I, _I],
}


def _load():
    if not _LIB_PATH.exists():
        raise RuntimeError(
            f"{_LIB_PATH} not found; run `bash build/build.sh` first"
        )
    lib = ctypes.CDLL(str(_LIB_PATH))
    for name, argtypes in _SIGNATURES.items():
        fn = getattr(lib, name)
        fn.restype = _RET
        fn.argtypes = argtypes
    return lib


lib = _load()

#: Longest error-code run the matcher will accept, in bytes.
MAX_CODE = 64
#: Longest error-code list a single comment may carry.
MAX_CODES = 32


def source_hash(source) -> bytes:
    """SHA-1 of the source bytes, the 20-byte digest `ast_serialize` reports.

    Accepts `bytes` or `str`; a `str` is encoded as UTF-8, which is what the
    upstream parser does before hashing.
    """
    data = source if isinstance(source, (bytes, bytearray)) else \
        str(source).encode("utf-8")
    buf = np.frombuffer(bytes(data), dtype=np.uint8)
    out = np.empty(20, dtype=np.uint8)
    w = np.zeros(80, dtype=np.uint32)
    lib.astsha1(buf.ctypes.data, buf.size, w.ctypes.data, out.ctypes.data)
    return out.tobytes()


def comments(source, cap: int = 4096):
    """The Python comments in `source` as (offset, length, line) triples."""
    buf = np.frombuffer(source, dtype=np.uint8)
    offs = np.zeros(cap, dtype=np.int64)
    lens = np.zeros(cap, dtype=np.int64)
    lines = np.zeros(cap, dtype=np.int64)
    n = int(lib.ast_comments(buf.ctypes.data, buf.size, offs.ctypes.data,
                             lens.ctypes.data, lines.ctypes.data, cap))
    return [(int(offs[i]), int(lens[i]), int(lines[i])) for i in range(n)]


def match_type_ignore(comment: bytes):
    """Match one comment body against `# type: ignore[...]`.

    Returns None when the comment is not a type-ignore, otherwise the list of
    error-code strings. `comment` must include the leading `#`.
    """
    buf = np.frombuffer(comment, dtype=np.uint8)
    recs = np.zeros(MAX_CODES, dtype=np.int64)
    lens = np.zeros(MAX_CODES, dtype=np.int64)
    blob = np.zeros(MAX_CODES * MAX_CODE, dtype=np.uint8)
    count = np.zeros(1, dtype=np.int64)
    rc = int(lib.ast_match_type_ignore(buf.ctypes.data, buf.size,
                                       recs.ctypes.data, lens.ctypes.data,
                                       blob.ctypes.data, MAX_CODES,
                                       count.ctypes.data))
    if rc == 0:
        return None
    n = int(count[0])
    return [bytes(blob[i * MAX_CODE:i * MAX_CODE + int(lens[i])]).decode("ascii")
            for i in range(n)]


def type_ignores(source, cap: int = 4096):
    """The `mypy_ignores` value `ast_serialize.parse` reports for `source`.

    Returns a list of `(line, [code, ...])` pairs, in source order.
    """
    out = []
    for off, length, line in comments(source, cap=cap):
        codes = match_type_ignore(source[off:off + length])
        if codes is not None:
            out.append((line, codes))
    return out
