""" Snapshot (golden) tests of the whole generated message for deterministic cases.

Snapshots live in tests/__snapshots__/. After an intended output change, review and regenerate them:
`pytest tests/test_snapshots.py --snapshot-update`. Random MIME boundaries are normalized; Date is disabled.
"""
import pytest

from envelope import Envelope
from helpers import IMAGE_FILE, TEXT_ATTACHMENT, normalize_boundaries

pytest.importorskip("syrupy")


def base() -> Envelope:
    return (Envelope("Hello world.")
            .subject("Snapshot")
            .from_("Sender <sender@example.com>")
            .to("Recipient <to@example.com>")
            .date(False))


CASES = {
    "plain": lambda: base(),
    "plain-and-html": lambda: base().message("<b>Hello</b> world.", alternative="html"),
    "html-only": lambda: base().message("<b>Hello</b> world.").mime("html"),
    "attachment": lambda: base().attach(TEXT_ATTACHMENT),
    "inline-image": lambda: base().message("<img src='cid:image.gif'>", alternative="html")
    .attach(IMAGE_FILE, inline=True),
    "recipients-and-headers": lambda: base()
    .cc("Čeněk <cc@example.com>")
    .bcc("bcc@example.com")
    .reply_to("reply@example.com")
    .header("X-Custom", "value"),
    "utf-8": lambda: base().subject("Příliš žluťoučký kůň").message("úpěl ďábelské ódy"),
    "long-line-base64": lambda: base().message("Longer than thousand chars. " * 40),
}


@pytest.mark.parametrize("build", CASES.values(), ids=CASES.keys())
def test_message_snapshot(build, snapshot):
    assert normalize_boundaries(build()) == snapshot
