import time
from concurrent.futures import ThreadPoolExecutor

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


def test_send_reports_success(smtp_server):
    assert Envelope("hello").from_("sender@example.com").to("to@example.com").smtp("localhost", smtp_server.port).send()


def test_send_partially_refused_still_succeeds(smtp_server, caplog):
    smtp_server.rejected.add("refused@example.com")
    assert (Envelope("hello")
            .from_("sender@example.com")
            .to("to@example.com, refused@example.com")
            .smtp("localhost", smtp_server.port)
            .send())
    [received] = smtp_server.messages
    assert received.rcpt_tos == ["to@example.com"]
    assert any("Unable to send to all recipients" in m and "refused@example.com" in m for m in caplog.messages)


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
def test_cli_send_with_smtp_host_port_delivers(smtp_server, cli):
    output = cli("--from", "sender@example.com", "--to", "to@example.com", "--smtp", "localhost", smtp_server.port, "--send", stdin="cli message")
    assert "Traceback" not in output
    assert len(smtp_server.messages) == 1


def test_send_without_from_is_refused(smtp_server, caplog):
    assert not Envelope("hello").to("to@example.com").smtp("localhost", smtp_server.port).send()
    assert not smtp_server.messages
    assert "You have to specify From e-mail." in caplog.messages


def test_send_fails_when_every_attempt_times_out(monkeypatch, caplog):
    class TimingOut:
        def ehlo_or_helo_if_needed(self):
            pass

        def sendmail(self, *args, **kwargs):
            raise TimeoutError

    monkeypatch.setattr(SMTPHandler, "_instances", {})
    monkeypatch.setattr(SMTPHandler, "connect", lambda self: TimingOut())
    e = Envelope("hello").from_("sender@example.com").to("to@example.com").smtp(attempts=2, delay=0)
    assert not e.send()
    assert any("timed out 2 times" in m for m in caplog.messages)


def test_send_retries_with_exponential_backoff(monkeypatch):
    """ Delays between attempts double, capped; no needless sleep after the last attempt. """
    class TimingOut:
        def ehlo_or_helo_if_needed(self):
            pass

        def sendmail(self, *args, **kwargs):
            raise TimeoutError

    sleeps = []
    monkeypatch.setattr("envelope.smtp_handler.sleep", sleeps.append)
    monkeypatch.setattr(SMTPHandler, "_instances", {})
    monkeypatch.setattr(SMTPHandler, "connect", lambda self: TimingOut())
    e = Envelope("hello").from_("sender@example.com").to("to@example.com").smtp(attempts=6, delay=5)
    assert not e.send()
    assert sleeps == [5, 10, 20, 40, 60]


@pytest.mark.cli
def test_cli_blank_smtp_means_default_server(cli):
    output = cli("--smtp", "--preview", stdin="hello")
    assert "Traceback" not in output
    assert "hello" in output


@pytest.mark.cli
@pytest.mark.parametrize("value", ["0", "false", "NO"])
def test_cli_smtp_off_switches_to_sendmail(cli, monkeypatch, value):
    calls = []
    monkeypatch.setattr(Envelope, "_deliver_sendmail", lambda self, *args: calls.append(args) or [])
    output = cli("--from", "sender@example.com", "--to", "to@example.com", "--smtp", value, "--send",
                 stdin="hello")
    assert "Traceback" not in output
    assert len(calls) == 1


def test_send_internationalized_address(monkeypatch):
    """ A non-ASCII address is sent with SMTPUTF8 when the server supports it. """
    controller_module = pytest.importorskip("aiosmtpd.controller")
    import socket

    class Handler:
        messages = []

        async def handle_DATA(self, server, session, envelope):
            self.messages.append(envelope)
            return "250 OK"

    with socket.socket() as s:
        s.bind(("localhost", 0))
        port = s.getsockname()[1]
    handler = Handler()
    controller = controller_module.Controller(handler, hostname="localhost", port=port, enable_SMTPUTF8=True)
    controller.start()
    monkeypatch.setattr(SMTPHandler, "_instances", {})
    try:
        assert Envelope("hello").from_("odesílatel@příklad.cz").to("to@example.com").smtp("localhost", port).send()
    finally:
        SMTPHandler.quit_all()
        controller.stop()
    [received] = handler.messages
    assert received.mail_from == "odesílatel@příklad.cz"
    assert "SMTPUTF8" in received.mail_options



def test_send_from_threads_does_not_share_connection_concurrently(monkeypatch):
    """ Threads sending through the same SMTP config get the same cached connection, one at a time. """
    class Connection:
        busy = False
        sent = 0

        def ehlo_or_helo_if_needed(self):
            pass

        def sendmail(self, *args, **kwargs):
            assert not self.busy, "two threads are using one SMTP connection at once"
            self.busy = True
            time.sleep(0.01)
            self.busy = False
            self.sent += 1
            return {}

    connection = Connection()
    monkeypatch.setattr(SMTPHandler, "_instances", {})
    monkeypatch.setattr(SMTPHandler, "connect", lambda self: connection)

    def send(i):
        return Envelope(f"message {i}").from_("sender@example.com").to("to@example.com").smtp(attempts=1).send()

    with ThreadPoolExecutor(8) as pool:
        assert all(pool.map(send, range(16)))
    assert connection.sent == 16
