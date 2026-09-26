"""mojo-ast-serialize: the byte-level work behind `ast_serialize`.

The Python package is named `mojo_ast_serialize`, so it installs alongside the
real `ast_serialize` and never shadows it. `ast_serialize` is a compiled Rust
extension; the two functions of it that are pure byte-level work, and that this
port reimplements, are the source hash it uses as its AST cache key and the
`# type: ignore[...]` scan it runs on every parse.
"""

from ._lib import (
    MAX_CODE,
    MAX_CODES,
    comments,
    match_type_ignore,
    source_hash,
    type_ignores,
)

__all__ = [
    "MAX_CODE",
    "MAX_CODES",
    "comments",
    "match_type_ignore",
    "source_hash",
    "type_ignores",
]
__version__ = "0.1.0"
