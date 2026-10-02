import pytest

from envelope import Envelope

AUTH_PASS = """Authentication-Results: mx.server;
       dkim=pass header.i=@example.com header.s=pf2023 header.b=XY;
       spf=pass (server: domain of noreply@example.com designates 1.1.1.1 as permitted sender) smtp.mailfrom=noreply@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
Received-SPF: {} (server: domain of noreply@example.com designates 1.1.1.1 as permitted sender) client-ip=1.1.1.1;
       """


@pytest.mark.parametrize(("message", "expected"), [
    ("Received-SPF: pass (...)", True),
    ("Subject: None", True),
    ("Received-SPF: fail (...)", False),
    (AUTH_PASS.format("pass"), True),
    (AUTH_PASS.format("softfail"), False),
    ("""Authentication-Results: mail.nic.cz;
	dkim=none;
	spf=pass (mail.nic.cz: domain of tomas.vecera22@pcr.cz designates 185.17.213.134 as permitted sender) smtp.mailfrom=tomas.vecera22@pcr.cz;
	dmarc=none""", True),
], ids=["spf-pass", "no-auth-headers", "spf-fail", "all-pass", "spf-softfail", "dkim-dmarc-none"])
def test_check_auth(message, expected):
    assert bool(Envelope.load(message)._check_auth()) is expected
