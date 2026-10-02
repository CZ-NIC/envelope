import pytest

from envelope import Envelope
from helpers import SMTP_CONFIG


@pytest.mark.parametrize(("kwargs", "expected"), [
    ({}, {"host": "localhost", "port": 25, "timeout": 3, "attempts": 3, "delay": 3}),
    ({"port": 32}, {"host": "localhost", "port": 32}),
    ({"timeout": 5}, {"timeout": 5}),
], ids=["defaults", "port", "timeout"])
def test_smtp_parameters(kwargs, expected):
    assert expected.items() <= Envelope().smtp(**kwargs)._smtp.__dict__.items()


def test_smtp_parameters_from_config_file():
    expected = {"timeout": 3, "user": "envelope-example-identity@example.com", "password": "", "port": 123}
    assert expected.items() <= Envelope().smtp(str(SMTP_CONFIG))._smtp.__dict__.items()


@pytest.mark.cli
def test_cli_json_dict(cli):
    """ --smtp accepts a plain JSON dict, same as before the jsonpickle -> json switch. """
    out = cli("--smtp", '{"host": "localhost", "port": 25}', "--preview", stdin="hello")
    assert "hello" in out
    assert "Traceback" not in out


@pytest.mark.cli
def test_cli_json_rejects_unknown_key(cli):
    """ A key outside the whitelist (host/port/user/password/security/timeout/attempts/delay/local_hostname)
    is rejected instead of being silently deserialized into arbitrary attributes. """
    out = cli("--smtp", '{"host": "localhost", "unknown_key": 1}', "--preview", stdin="hello")
    assert "Unknown --smtp key" in out


@pytest.mark.cli
def test_cli_json_rejects_malformed_json(cli):
    """ Malformed JSON fails with a clear error instead of a jsonpickle-style traceback. """
    out = cli("--smtp", "{bad json", "--preview", stdin="hello")
    assert "Invalid JSON in --smtp" in out


@pytest.mark.cli
def test_cli_json_rejects_object_payload(cli):
    """ A jsonpickle-style `py/object` payload is no longer deserialized into an arbitrary object;
    it is rejected as an unknown key. """
    out = cli("--smtp", '{"py/object": "os.system", "host": "localhost"}', "--preview", stdin="hello")
    assert "Unknown --smtp key" in out
