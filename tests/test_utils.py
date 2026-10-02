from io import StringIO

import pytest

from envelope.utils import assure_list, assure_fetched


@pytest.mark.parametrize(("value", "expected"), [
    (None, []),
    ("test", ["test"]),
    (5, [5]),
    (False, [False]),
    (b"test", [b"test"]),
    ((x for x in range(3)), [0, 1, 2]),
    ([x for x in range(3)], [0, 1, 2]),
    ({x: "nothing" for x in range(3)}, [0, 1, 2]),
    ({x: "nothing" for x in range(3)}.keys(), [0, 1, 2]),
    (("one", "two"), ["one", "two"]),
], ids=["none", "str", "int", "false", "bytes", "generator", "list", "dict", "dict-keys", "tuple"])
def test_assure_list(value, expected):
    assert assure_list(value) == expected


@pytest.mark.parametrize(("value", "expected"), [
    ({0, 1, 2}, [0, 1, 2]),
    (frozenset(("one", "two")), ["one", "two"]),
], ids=["set", "frozenset"])
def test_assure_list_unordered(value, expected):
    assert sorted(assure_list(value)) == sorted(expected)


@pytest.mark.parametrize(("value", "type_", "expected"), [
    ("test", bytes, b"test"),
    ("test", str, "test"),
    (False, str, False),
    (None, str, None),
    (b"test", bytes, b"test"),
    (b"test", str, "test"),
    (StringIO("test"), str, "test"),
    (StringIO("test"), bytes, b"test"),
])
def test_assure_fetched(value, type_, expected):
    assert assure_fetched(value, type_) == expected
