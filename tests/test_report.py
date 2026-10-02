import logging

import pytest

from envelope import Envelope
from helpers import EML_DIR

XARF = EML_DIR / "multipart-report-xarf.eml"


def test_no_report_in_empty_envelope():
    assert not Envelope()._report()


def test_loading_xarf():
    report = Envelope.load(XARF)._report()
    assert {"ReporterOrg": "Example"}.items() <= report["ReporterInfo"].items()
    assert {"SourceIp": "192.0.2.1"}.items() <= report["Report"].items()


@pytest.mark.parametrize(("old", "new", "message"), [
    # only `Content-Type: message/feedback-report` is implemented within `multipart/report`
    ("Content-Type: message/feedback-report", "Content-Type: message/UNSUPPORTED",
     "Message might not have been loaded correctly. Parsing multipart/report / message/unsupported not implemented."),
    # `Content-Type: message` is not implemented within `multipart/mixed`
    ("Content-Type: multipart/report", "Content-Type: multipart/mixed",
     "Message might not have been loaded correctly. "
     "Parsing multipart/mixed / message/feedback-report failed or not implemented."),
], ids=["unsupported-message-in-report", "message-in-mixed"])
def test_unsupported_message_warns(caplog, old, new, message):
    text = XARF.read_text().replace(old, new)
    with caplog.at_level(logging.WARNING, logger="envelope"):
        Envelope.load(text)
    assert [(r.name, r.levelname, r.getMessage()) for r in caplog.records] == [
        ("envelope.envelope", "WARNING", message)]
