from email.message import EmailMessage
from smtplib import SMTPServerDisconnected
from unittest import mock

from envelope import Envelope
from envelope.smtp_handler import SMTPHandler


def test_copy_is_independent():
    factory = Envelope().cc("original@example.com").copy
    e1 = factory().to("independent-1@example.com")
    e2 = factory().to("independent-2@example.com").cc("additional@example.com")

    assert e1.recipients() == {"independent-1@example.com", "original@example.com"}
    assert e2.recipients() == {"independent-2@example.com", "original@example.com", "additional@example.com"}


def test_as_message():
    e = Envelope("hello").as_message()
    assert type(e) is EmailMessage
    assert e.get_payload() == "hello\n"


def test_smtp_quit_object_closes_only_its_connection_class_closes_all(monkeypatch, capsys):
    """ Calling .smtp_quit() on an object closes only its current SMTP connection,
        calling on the class closes them all. A closed connection is dropped from the cache. """

    class DummySMTPConnection:
        def __init__(self, name):
            self.name = name

        def quit(self):
            print(self.name)

    def key(name):
        return "{'host': '" + name + "', 'port': 25, 'user': None, 'password': None," \
                                     " 'security': None, 'timeout': 3, 'attempts': 3, 'delay': 3, 'local_hostname': None}"

    monkeypatch.setattr(SMTPHandler, "_instances",
                        {key(name): DummySMTPConnection(name) for name in (f"dummy{i}" for i in range(4))})

    e1 = Envelope().smtp("dummy1").smtp("dummy2")  # this object uses dummy2 only
    e2 = Envelope().smtp("dummy3")  # this object uses dummy3

    e2.smtp_quit()
    Envelope.smtp_quit()
    e1.smtp_quit()
    Envelope.smtp_quit()
    expected = [f"dummy{i}" for i in [3, 0, 1, 2]]
    assert capsys.readouterr().out.split() == expected
    assert not SMTPHandler._instances


def test_smtp_failed_connection_not_cached(monkeypatch):
    """ A failed connection must not be cached, otherwise .smtp_quit() fails on a bool. (#60) """
    monkeypatch.setattr(SMTPHandler, "_instances", {})
    handler = SMTPHandler("failing-host")
    with mock.patch.object(SMTPHandler, "connect", return_value=False):
        assert not handler.send_message(None, "from@example.com", ["to@example.com"])
    assert handler.key not in SMTPHandler._instances
    Envelope.smtp_quit()  # does not raise AttributeError


def test_smtp_quit_tolerates_dropped_connection(monkeypatch):
    """ A connection already closed by the server must not crash .smtp_quit() nor stay cached. """
    class Dropped:
        def quit(self):
            raise SMTPServerDisconnected("Connection unexpectedly closed")

    monkeypatch.setattr(SMTPHandler, "_instances", {"a": Dropped(), "b": Dropped()})
    Envelope.smtp_quit()
    assert not SMTPHandler._instances


def test_send_after_smtp_quit_reconnects(smtp_server):
    def send():
        return Envelope("hello").from_("sender@example.com").to("to@example.com").smtp("localhost", smtp_server.port).send()

    assert send()
    Envelope.smtp_quit()
    assert not SMTPHandler._instances
    assert send()
    assert len(smtp_server.messages) == 2
