from dataclasses import dataclass
from email.message import EmailMessage
import re
from typing import Optional


@dataclass
class AuthResult:
    verdict: str
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    spf_received: Optional[str] = None
    failure_reason: Optional[str] = None

    def __bool__(self):
        return self.verdict == "pass"

    def __repr__(self):
        return (f"<AuthResult spf={self.spf!r}, dkim={self.dkim!r}, dmarc={self.dmarc!r}, "
                f"spf_received={self.spf_received!r}, verdict={self.verdict!r}, failure_reason={self.failure_reason!r}>")

    @staticmethod
    def _extract_results_from_text(text: str) -> dict:
        def extract(key: str):
            match = re.search(fr"{key}=([\w\-]+)", text, re.IGNORECASE)
            return match.group(1).lower() if match else None

        return extract("spf"), extract("dkim"), extract("dmarc")

    @staticmethod
    def from_headers(headers: EmailMessage) -> "AuthResult":

        # Merge Authentication-Results and ARC-Authentication-Results hlavičky dohromady
        auth_results_headers: list[str] = []
        auth_results_headers += headers.get_all("Authentication-Results", [])
        auth_results_headers += headers.get_all("ARC-Authentication-Results", [])

        combined_auth_results = "; ".join(auth_results_headers)

        # Extract from text
        spf, dkim, dmarc = AuthResult._extract_results_from_text(combined_auth_results)

        # SPF from Received-SPF
        received_spf = headers.get("Received-SPF", "")
        spf_received_match = re.search(r"([\w\-]+)", received_spf)
        spf_received = spf_received_match.group(1).lower() if spf_received_match else None

        # Determine the verdict
        failure_reason = None
        if spf and spf_received and spf != spf_received:
            verdict = "fail"
            failure_reason = f"SPF mismatch: Authentication-Results={spf}, Received-SPF={spf_received}"

        elif dmarc == "pass":
            verdict = "pass"

        elif any(v == "fail" for v in [spf, dkim, dmarc, spf_received]):
            verdict = "fail"
            failure_reason = "At least one mechanism failed"

        elif any(v == "softfail" for v in [spf, spf_received]):
            verdict = "softfail"
            failure_reason = "SPF softfail detected"

        elif all(v == "pass" for v in [spf, dkim] if v and v != 'none'):
            verdict = "pass"
        else:
            verdict = "none"
            failure_reason = "No usable authentication results"

        return AuthResult(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            spf_received=spf_received,
            verdict=verdict,
            failure_reason=failure_reason
        )
