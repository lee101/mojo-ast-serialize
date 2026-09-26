"""Byte-level kernels for `mojo-ast-serialize`.

`ast_serialize` is a compiled Rust extension that parses Python source and, on
every call, computes two things that are pure byte-level work and are returned
in its result tuple:

* `source_hash`, the SHA-1 of the source bytes, which is the cache key for the
  parsed AST, and
* `mypy_ignores`, the list of `(line, [error code, ...])` pairs found in
  `# type: ignore[...]` comments.

Both are ported here. The second needs to know which `#` characters begin a
real comment and which sit inside a string literal, so the Python comment lexer
is exported on its own as `ast_comments`, and the grammar matcher as
`ast_match_type_ignore`.

Every exported symbol takes buffer addresses as plain `Int` values and rebuilds
the pointer inside the body, because `@export` rejects parametric functions and
an inferred pointer origin would make the symbol parametric.
"""

comptime BPtr = Pointer[UInt8, AnyOrigin[mut=True]]
comptime U32Ptr = Pointer[UInt32, AnyOrigin[mut=True]]
comptime I64Ptr = Pointer[Int64, AnyOrigin[mut=True]]


def bp(addr: Int) -> BPtr:
    return BPtr(unsafe_from_address=addr)


def i64p(addr: Int) -> I64Ptr:
    return I64Ptr(unsafe_from_address=addr)


# --------------------------------------------------------------------------
# SHA-1, the source cache key.
# --------------------------------------------------------------------------


def _rol(x: UInt32, n: UInt32) -> UInt32:
    return (x << n) | (x >> (32 - n))


def _store_be(out_ptr: BPtr, at: Int, value: UInt32):
    for k in range(4):
        out_ptr[unsafe_offset=at + k] = UInt8(
            (value >> UInt32(8 * (3 - k))) & UInt32(0xFF)
        )


@export("astsha1")
def astsha1(data_addr: Int, nbytes: Int, w_addr: Int, out_addr: Int) abi("C"):
    """Write the 20-byte SHA-1 digest of `data` to `out`.

    FIPS 180-4. The message padding is produced on the fly from the byte index
    rather than copied into a buffer, so the only scratch memory is the
    80-word message schedule, which the caller supplies at `w_addr` (320 bytes
    of `UInt32`). Keeping the scratch in the caller's hands is the same rule
    the rest of this ABI follows: the library owns no memory.
    """
    var data = bp(data_addr)
    var out = bp(out_addr)
    var w = U32Ptr(unsafe_from_address=w_addr)

    var h0 = UInt32(0x67452301)
    var h1 = UInt32(0xEFCDAB89)
    var h2 = UInt32(0x98BADCFE)
    var h3 = UInt32(0x10325476)
    var h4 = UInt32(0xC3D2E1F0)

    # Total padded length: message, one 0x80 byte, zeros, then the 64-bit
    # big-endian bit count.
    var padlen = nbytes + 1
    while padlen % 64 != 56:
        padlen += 1
    padlen += 8
    var bitlen = UInt64(nbytes) * 8

    for blk in range(padlen // 64):
        var base = blk * 64
        for j in range(16):
            var word = UInt32(0)
            for b in range(4):
                var p = base + 4 * j + b
                var byte = UInt8(0)
                if p < nbytes:
                    byte = data[unsafe_offset=p]
                elif p == nbytes:
                    byte = UInt8(0x80)
                elif p >= padlen - 8:
                    # Big-endian: the most significant length byte comes first.
                    byte = UInt8(
                        (bitlen >> UInt64(8 * (padlen - 1 - p))) & UInt64(0xFF)
                    )
                word = (word << UInt32(8)) | UInt32(byte)
            w[unsafe_offset=j] = word
        for j in range(16, 80):
            var v = w[unsafe_offset=j - 3] ^ w[unsafe_offset=j - 8]
            v = v ^ w[unsafe_offset=j - 14] ^ w[unsafe_offset=j - 16]
            w[unsafe_offset=j] = _rol(v, UInt32(1))

        var a = h0
        var b = h1
        var c = h2
        var d = h3
        var e = h4
        for r in range(80):
            var f: UInt32
            var k: UInt32
            if r < 20:
                f = (b & c) | ((~b) & d)
                k = UInt32(0x5A827999)
            elif r < 40:
                f = b ^ c ^ d
                k = UInt32(0x6ED9EBA1)
            elif r < 60:
                f = (b & c) | (b & d) | (c & d)
                k = UInt32(0x8F1BBCDC)
            else:
                f = b ^ c ^ d
                k = UInt32(0xCA62C1D6)
            var tmp = _rol(a, UInt32(5)) + f + e
            tmp = tmp + k + w[unsafe_offset=r]
            e = d
            d = c
            c = _rol(b, UInt32(30))
            b = a
            a = tmp
        h0 = h0 + a
        h1 = h1 + b
        h2 = h2 + c
        h3 = h3 + d
        h4 = h4 + e

    _store_be(out, 0, h0)
    _store_be(out, 4, h1)
    _store_be(out, 8, h2)
    _store_be(out, 12, h3)
    _store_be(out, 16, h4)


# --------------------------------------------------------------------------
# Python comment lexer.
# --------------------------------------------------------------------------


@export("ast_comments")
def ast_comments(
    src_addr: Int, nbytes: Int, off_addr: Int, len_addr: Int, line_addr: Int,
    cap: Int
) abi("C") -> Int:
    """Return the number of comments found and fill their spans.

    Writes, for each comment, the byte offset of its `#`, its length including
    the `#`, and its 1-based line number, into three parallel arrays of
    capacity `cap`. A `#` inside a string literal is not a comment.

    Escapes are honoured inside every string form, which is what the upstream
    tokenizer does: it reports the `#` in `r"\\""` as string content, not as a
    comment.
    """
    var src = bp(src_addr)
    var offs = i64p(off_addr)
    var lens = i64p(len_addr)
    var lines = i64p(line_addr)
    var n = 0
    var i = 0
    var line = 1
    while i < nbytes:
        var ch = src[unsafe_offset=i]
        if ch == UInt8(0x0A):
            line += 1
            i += 1
        elif ch == UInt8(0x23):  # '#'
            var j = i
            while j < nbytes and src[unsafe_offset=j] != UInt8(0x0A):
                j += 1
            if n < cap:
                offs[unsafe_offset=n] = Int64(i)
                lens[unsafe_offset=n] = Int64(j - i)
                lines[unsafe_offset=n] = Int64(line)
                n += 1
            i = j
        elif ch == UInt8(0x27) or ch == UInt8(0x22):  # quote
            var quote = ch
            var triple = (
                i + 2 < nbytes
                and src[unsafe_offset=i + 1] == quote
                and src[unsafe_offset=i + 2] == quote
            )
            var k = i + 3 if triple else i + 1
            var closed = False
            while k < nbytes:
                var c = src[unsafe_offset=k]
                if c == UInt8(0x5C):  # backslash escape
                    if k + 1 < nbytes:
                        if src[unsafe_offset=k + 1] == UInt8(0x0A):
                            line += 1
                        k += 2
                        continue
                    k += 1
                    continue
                if c == UInt8(0x0A):
                    line += 1
                if triple:
                    if (
                        c == quote
                        and k + 2 < nbytes
                        and src[unsafe_offset=k + 1] == quote
                        and src[unsafe_offset=k + 2] == quote
                    ):
                        k += 3
                        closed = True
                        break
                    k += 1
                else:
                    if c == quote:
                        k += 1
                        closed = True
                        break
                    k += 1
            if not closed:
                break
            i = k
        else:
            i += 1
    return n


# --------------------------------------------------------------------------
# `# type: ignore[...]` matcher.
# --------------------------------------------------------------------------

def _is_space(src: BPtr, i: Int, n: Int) -> Bool:
    """Whitespace as the upstream tokenizer sees it.

    ASCII whitespace plus the Unicode space separators that appear in source
    files: U+0085, U+00A0, U+1680, U+2000..U+200A, U+2028, U+2029, U+202F,
    U+205F and U+3000.
    """
    if i >= n:
        return False
    var c = src[unsafe_offset=i]
    if (
        c == UInt8(0x20)
        or c == UInt8(0x09)
        or c == UInt8(0x0A)
        or c == UInt8(0x0B)
        or c == UInt8(0x0C)
        or c == UInt8(0x0D)
    ):
        return True
    if c == UInt8(0xC2) and i + 1 < n:
        var c1 = src[unsafe_offset=i + 1]
        return c1 == UInt8(0x85) or c1 == UInt8(0xA0)
    if c == UInt8(0xE1) and i + 2 < n:
        return (
            src[unsafe_offset=i + 1] == UInt8(0x9A)
            and src[unsafe_offset=i + 2] == UInt8(0x80)
        )
    if c == UInt8(0xE2) and i + 2 < n:
        var c1 = src[unsafe_offset=i + 1]
        var c2 = src[unsafe_offset=i + 2]
        if c1 == UInt8(0x80):
            return (
                c2 <= UInt8(0x8A)
                or c2 == UInt8(0xA8)
                or c2 == UInt8(0xA9)
                or c2 == UInt8(0xAF)
            )
        return c1 == UInt8(0x81) and c2 == UInt8(0x9F)
    if c == UInt8(0xE3) and i + 2 < n:
        return (
            src[unsafe_offset=i + 1] == UInt8(0x80)
            and src[unsafe_offset=i + 2] == UInt8(0x80)
        )
    return False


def _space_len(src: BPtr, i: Int, n: Int) -> Int:
    """The byte width of the whitespace character at `i`, or 0.

    A width is needed because the Unicode space separators are multi-byte: a
    boolean test that consumed one byte at a time would leave the continuation
    bytes in place and the grammar would then fail on them.
    """
    if not _is_space(src, i, n):
        return 0
    if src[unsafe_offset=i] < UInt8(0x80):
        return 1
    if src[unsafe_offset=i] == UInt8(0xC2):
        return 2
    return 3


def _skip_space(src: BPtr, i: Int, n: Int) -> Int:
    var p = i
    while True:
        var width = _space_len(src, p, n)
        if width == 0:
            return p
        p += width


def _is_code_char(c: UInt8) -> Bool:
    """ASCII alphanumerics plus `_` and `-`, the shape of a mypy error code."""
    if (c >= UInt8(0x30) and c <= UInt8(0x39)) \
            or (c >= UInt8(0x41) and c <= UInt8(0x5A)) \
            or (c >= UInt8(0x61) and c <= UInt8(0x7A)):
        return True
    return c == UInt8(0x5F) or c == UInt8(0x2D)


@export("ast_match_type_ignore")
def ast_match_type_ignore(
    cmt_addr: Int, cmt_len: Int, rec_off_addr: Int, rec_len_addr: Int,
    blob_addr: Int, blob_cap: Int, count_addr: Int
) abi("C") -> Int:
    """Match one comment against the `# type: ignore[...]` grammar.

    Returns 1 when the comment is a type-ignore and 0 otherwise. On a match the
    error-code spans are written as (offset, length) pairs relative to the
    comment start into `rec_off` / `rec_len`, the code bytes are appended to
    the `blob` arena, and the number of codes is written to `count`.

    The grammar, as observed from the upstream implementation:

        comment := WS* "type:" WS* "ignore" ( WS* "[" codes "]" )? WS* EOF
        codes   := ( code ( WS* "," )* WS* )*
        code    := [A-Za-z0-9_-]+

    Anything else, including a trailing character after `]`, is not a
    type-ignore. Upstream also accepts Unicode alphanumerics in a code; this
    port restricts codes to ASCII, which is documented in the README.
    """
    var src = bp(cmt_addr)
    var recs = i64p(rec_off_addr)
    var lens = i64p(rec_len_addr)
    var blob = bp(blob_addr)
    var counts = i64p(count_addr)
    var n = cmt_len
    counts[unsafe_offset=0] = 0

    # The span includes the leading '#', which is not part of the grammar.
    if n < 1 or src[unsafe_offset=0] != UInt8(0x23):
        return 0
    var i = _skip_space(src, 1, n)
    # "type:"
    if i + 5 > n:
        return 0
    if src[unsafe_offset=i] != UInt8(0x74) or src[unsafe_offset=i + 1] != UInt8(0x79) \
            or src[unsafe_offset=i + 2] != UInt8(0x70) \
            or src[unsafe_offset=i + 3] != UInt8(0x65) \
            or src[unsafe_offset=i + 4] != UInt8(0x3A):
        return 0
    i += 5
    i = _skip_space(src, i, n)
    # "ignore"
    if i + 6 > n:
        return 0
    if src[unsafe_offset=i] != UInt8(0x69) or src[unsafe_offset=i + 1] != UInt8(0x67) \
            or src[unsafe_offset=i + 2] != UInt8(0x6E) \
            or src[unsafe_offset=i + 3] != UInt8(0x6F) \
            or src[unsafe_offset=i + 4] != UInt8(0x72) \
            or src[unsafe_offset=i + 5] != UInt8(0x65):
        return 0
    i += 6
    if i < n and not _is_space(src, i, n) and src[unsafe_offset=i] != UInt8(0x5B):
        return 0
    i = _skip_space(src, i, n)
    if i >= n:
        return 1
    # After `ignore` only a further `#` (a second comment on the same line) or
    # the bracketed code list is accepted.
    if src[unsafe_offset=i] == UInt8(0x23):
        return 1
    if src[unsafe_offset=i] != UInt8(0x5B):
        return 0
    i += 1

    var ncodes = 0
    while True:
        i = _skip_space(src, i, n)
        if i >= n:
            return 0
        if src[unsafe_offset=i] == UInt8(0x5D):
            i += 1
            break
        if src[unsafe_offset=i] == UInt8(0x2C):
            i += 1
            continue
        var start = i
        while i < n and _is_code_char(src[unsafe_offset=i]):
            i += 1
        if i == start:
            return 0
        if ncodes < blob_cap:
            recs[unsafe_offset=ncodes] = Int64(start)
            lens[unsafe_offset=ncodes] = Int64(i - start)
            for q in range(start, i):
                blob[unsafe_offset=ncodes * 64 + (q - start)] = src[
                    unsafe_offset=q
                ]
        ncodes += 1
        i = _skip_space(src, i, n)
        if i >= n:
            return 0
        if src[unsafe_offset=i] == UInt8(0x2C):
            i += 1
            continue
        if src[unsafe_offset=i] == UInt8(0x5D):
            i += 1
            break
        return 0
    i = _skip_space(src, i, n)
    if i != n:
        return 0
    counts[unsafe_offset=0] = Int64(ncodes)
    return 1
