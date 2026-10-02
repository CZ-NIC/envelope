import pytest

from envelope import Envelope
from envelope.smtp_handler import SMTPHandler
from helpers import IDENTITY_1, IDENTITY_2, MESSAGE, PGP_MESSAGE, SMTP_CONFIG


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


# Regression from b0a7d5b (2.4.0): `_send_now` treats `_deliver_now`'s empty "failed recipients" result as a failure,
# so a successful delivery leaves bool(envelope) False (and the CLI exits 1).
SEND_STATUS_BUG = pytest.mark.xfail(strict=True, reason="successful send reported as failure since b0a7d5b")


def test_send_delivers_to_real_server(smtp_server):
    (Envelope("hello")
     .subject("delivered")
     .from_("sender@example.com")
     .to("to@example.com")
     .cc("cc@example.com")
     .bcc("bcc@example.com")
     .smtp("localhost", smtp_server.port)
     .send())

    [received] = smtp_server.messages
    assert received.mail_from == "sender@example.com"
    assert sorted(received.rcpt_tos) == ["bcc@example.com", "cc@example.com", "to@example.com"]
    content = received.content.decode()
    assert "Subject: delivered" in content
    assert "hello" in content
    assert "bcc@example.com" not in content  # Bcc is an envelope recipient only, never a header


@SEND_STATUS_BUG
def test_send_reports_success(smtp_server):
    assert Envelope("hello").from_("sender@example.com").to("to@example.com").smtp("localhost", smtp_server.port).send()


def test_send_reports_failure_when_server_unreachable(smtp_server):
    e = Envelope("hello").from_("sender@example.com").to("to@example.com").smtp("localhost", smtp_server.port + 1, attempts=1, delay=0)
    assert not e.send()
    assert not smtp_server.messages


def test_send_uses_from_addr_as_envelope_sender(smtp_server):
    (Envelope("hello")
     .from_("header-from@example.com")
     .from_addr("envelope-from@example.com")
     .to("to@example.com")
     .smtp("localhost", smtp_server.port)
     .send())
    [received] = smtp_server.messages
    assert received.mail_from == "envelope-from@example.com"
    assert "From: header-from@example.com" in received.content.decode()


def test_send_reuses_cached_connection(smtp_server):
    for i in range(3):
        Envelope(f"message {i}").from_("sender@example.com").to("to@example.com").smtp("localhost", smtp_server.port).send()
    assert [m.content.decode().rstrip().splitlines()[-1] for m in smtp_server.messages] \
           == ["message 0", "message 1", "message 2"]
    assert len(SMTPHandler._instances) == 1


@pytest.mark.gpg
def test_send_encrypted_delivers_ciphertext(smtp_server, gpg_home):
    (Envelope(MESSAGE)
     .gpg(str(gpg_home))
     .from_(IDENTITY_1)
     .to(IDENTITY_2)
     .encryption()
     .smtp("localhost", smtp_server.port)
     .send())
    content = smtp_server.messages[0].content.decode()
    assert PGP_MESSAGE in content
    assert MESSAGE not in content


@pytest.mark.cli
def test_cli_send_with_smtp_dict_delivers(smtp_server, cli):
    cli("--from", "sender@example.com", "--to", "to@example.com", "--subject", "from cli",
        "--smtp", f'{{"host": "localhost", "port": {smtp_server.port}}}', "--send", stdin="cli message")
    [received] = smtp_server.messages
    assert received.rcpt_tos == ["to@example.com"]
    assert "Subject: from cli" in received.content.decode()


@pytest.mark.cli
@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="since b0a7d5b, `--smtp HOST PORT` crashes on list.lower() in __main__.py")
def test_cli_send_with_smtp_host_port_delivers(smtp_server, cli):
    output = cli("--from", "sender@example.com", "--to", "to@example.com", "--smtp", "localhost", smtp_server.port, "--send", stdin="cli message")
    assert "Traceback" not in output
    assert len(smtp_server.messages) == 1


def test_send_without_from_is_refused(smtp_server, caplog):
    assert not Envelope("hello").to("to@example.com").smtp("localhost", smtp_server.port).send()
    assert not smtp_server.messages
    assert "You have to specify From e-mail." in caplog.messages
