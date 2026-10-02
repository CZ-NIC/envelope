""" Regression + new coverage for the 2026-09-04 security review (see PLAN.md). """
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from unittest import mock

import pytest

from envelope import Envelope
from envelope.address import Address
from envelope.constants import SENDMAIL_PATH
from envelope.parser import Parser, MAX_PARSE_DEPTH
from envelope.utils import is_safe_argv_value


@pytest.mark.parametrize(("value", "expected"), [
    ("person@example.com", True),
    ("example.com", True),
    ("", False),
    ("-oQ/tmp/evil", False),
    ("--help", False),
    ("a b", False),
    ("a\tb", False),
    ("a\nb", False),
    ("a\rb", False),
], ids=["email", "domain", "empty", "short-option", "long-option", "space", "tab", "newline", "carriage-return"])
def test_is_safe_argv_value(value, expected):
    assert is_safe_argv_value(value) is expected


def _sendmail_envelope():
    e = Envelope().message("hello")
    e._sendmail = True
    return e


def test_deliver_sendmail_safe_from_addr_unchanged():
    """ Regression: a normal From address still reaches subprocess.run with the same argv as before. """
    e = _sendmail_envelope()
    with mock.patch("envelope.envelope.subprocess.run") as run:
        result = e._deliver_sendmail(str(e), "person@example.com", [])
    assert result == []
    run.assert_called_once()
    (args,), kwargs = run.call_args
    assert args == [SENDMAIL_PATH, "-t", "-oi", "-f", "person@example.com"]
    assert kwargs.get("input") == str(e)


@pytest.mark.parametrize("from_addr", [
    "-oQ/tmp/evil",  # looks like an extra CLI flag
    "person@example.com\nBcc: attacker@evil.com",  # control characters
], ids=["option-like", "control-chars"])
def test_deliver_sendmail_rejects_malicious_from_addr(from_addr):
    """ A malicious From address must never reach subprocess. """
    e = _sendmail_envelope()
    with mock.patch("envelope.envelope.subprocess.run") as run:
        result = e._deliver_sendmail(str(e), from_addr, [])
    assert not result
    run.assert_not_called()


def test_dig_safe_domain_unchanged():
    """ Regression: a normal domain still reaches subprocess.check_output as before,
    with the plain domain as the last, unmodified argv item. """
    e = Envelope()
    e._from = Address(address="person@example.com")
    with mock.patch("envelope.envelope.subprocess.check_output", return_value=b"") as check_output:
        e.check(check_mx=False, check_smtp=False)
    assert check_output.called
    (first_args,), _ = check_output.call_args_list[0]
    assert first_args == ["dig", "-t", "TXT", "example.com"]


def test_dig_rejects_malicious_domain():
    """ A From-header-derived domain that looks like a dig option must never itself be handed to
    subprocess as a bare argv value (it would be interpreted as another `dig` flag). """
    e = Envelope()
    e._from = Address(address="attacker@-evil.com")
    with mock.patch("envelope.envelope.subprocess.check_output", return_value=b"") as check_output:
        e.check(check_mx=False, check_smtp=False)
    calls = [args for (args,), _ in check_output.call_args_list]
    for args in calls:
        assert not args[-1].startswith("-"), f"unsafe dig query reached subprocess: {args[-1]!r}"
    # the direct, unprefixed lookup of the malicious domain must have been skipped entirely
    assert ["dig", "-t", "TXT", "-evil.com"] not in calls
    assert ["dig", "-t", "SPF", "-evil.com"] not in calls


def _nested(depth):
    msg = MIMEText("leaf", "plain")
    for _ in range(depth):
        outer = MIMEMultipart("mixed")
        outer.attach(msg)
        msg = outer
    return msg


def test_parser_depth_limit_raises():
    """ A pathologically nested MIME structure must raise instead of exhausting the call stack. """
    with pytest.raises(ValueError):
        Parser(Envelope()).parse(_nested(MAX_PARSE_DEPTH + 5))


def test_parser_depth_limit_allows_reasonable_nesting():
    """ Regression: nesting well under the cap still parses normally. """
    e = Parser(Envelope()).parse(_nested(MAX_PARSE_DEPTH - 5))
    assert e.message() == "leaf"
