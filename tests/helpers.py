""" Plain helper functions and constants shared by the test modules. Pytest fixtures live in conftest.py. """
import os
import re
from pathlib import Path
from subprocess import PIPE, STDOUT, run

FIXTURES = Path(__file__).parent / "fixtures"
EML_DIR = FIXTURES / "eml"
GPG_RING = FIXTURES / "gpg_ring"
GPG_KEYS = FIXTURES / "gpg_keys"
SMIME_DIR = FIXTURES / "smime"
SMIME_CHAINED_DIR = FIXTURES / "smime_chained"
SMTP_CONFIG = FIXTURES / "smtp-configuration.ini"

# sample messages
EML = EML_DIR / "mail.eml"
UTF_HEADER = EML_DIR / "utf-header.eml"  # the file has encoded headers
CHARSET = EML_DIR / "charset.eml"  # the file has encoded headers
INTERNATIONALIZED = EML_DIR / "internationalized.eml"
QUOPRI = EML_DIR / "quopri.eml"  # the file has CRLF separators
TEXT_ATTACHMENT = EML_DIR / "generic.txt"
IMAGE_FILE = EML_DIR / "image.gif"
GROUP_RECIPIENT = EML_DIR / "group-recipient.eml"
INVALID_CHARACTERS = EML_DIR / "invalid-characters.eml"
INVALID_HEADERS = EML_DIR / "invalid-headers.eml"

# GPG identities in the testing keyring
#   IDENTITY_1: no passphrase, fingerprint IDENTITY_1_GPG_FINGERPRINT
#   IDENTITY_2: passphrase GPG_PASSPHRASE, fingerprint 3C8124A8245618D286CF871E94CE2905DB00CDB7
#   IDENTITY_3: not in the keyring
GPG_PASSPHRASE = "test"
IDENTITY_1_GPG_FINGERPRINT = "F14F2E8097E0CCDE93C4E871F4A4F26779FA03BB"
IDENTITY_1 = "envelope-example-identity@example.com"
IDENTITY_2 = "envelope-example-identity-2@example.com"
IDENTITY_3 = "envelope-example-identity-3@example.com"

PGP_MESSAGE = "-----BEGIN PGP MESSAGE-----"
MESSAGE = "dumb message"

CLI_CMD = ("python3", "-m", "envelope")


def assert_lines(output, *lines: str, absent: str | tuple[str, ...] = (),
                 min_lines: int | None = None, max_lines: int | None = None) -> str:
    """ Convert `output` (ex: an Envelope) to str and assert its lines.

    :param lines: Every one of these lines must be present, in the given order (other lines may be in between).
    :param absent: None of these lines may be present.
    :param min_lines: The output must have more lines than this.
    :param max_lines: The output must have fewer lines than this.
    :return: The output as str, for further assertions.
    """
    text = str(output)
    output_lines = text.splitlines()

    long_lines = [line for line in output_lines if len(line) > 999]
    assert not long_lines, f"RFC 5322 line length limit exceeded: {long_lines[0][:80]}..."

    remaining = output_lines
    previous = ""
    for line in lines:
        try:
            index = remaining.index(line)
        except ValueError:
            problem = f"is in the wrong order (above the line {previous!r})" if line in output_lines else "not found"
            raise AssertionError(f"Line {line!r} {problem} in the output:\n{text}") from None
        remaining = remaining[index + 1:]
        previous = line

    if isinstance(absent, str):
        absent = absent,
    for line in absent:
        assert line not in output_lines, f"Line {line!r} should not be in the output:\n{text}"

    if min_lines is not None:
        assert len(output_lines) > min_lines, f"Expected more than {min_lines} lines, got {len(output_lines)}"
    if max_lines is not None:
        assert len(output_lines) < max_lines, f"Expected fewer than {max_lines} lines, got {len(output_lines)}"
    return text


def run_subprocess(*cmd: str | Path, stdin: str | bytes | Path = b"", env: dict | None = None,
                   decode=True) -> str | bytes:
    """ Run a command in a subprocess, stderr merged into stdout. Prefer the in-process `cli` fixture
    for envelope itself; use this for external tools (gpg, openssl) or real `python -m envelope` smoke tests. """
    if isinstance(stdin, Path):
        stdin = stdin.read_bytes()
    elif isinstance(stdin, str):
        stdin = stdin.encode()
    if env:
        env = {**os.environ, **{k: str(v) for k, v in env.items()}}
    result = run([str(c) for c in cmd], input=stdin, stdout=PIPE, stderr=STDOUT, env=env).stdout
    return result.decode().rstrip() if decode else result


def normalize_boundaries(text: str) -> str:
    """ Replace random MIME boundaries (`===============1234567890==`) with stable ones, for snapshot tests. """
    boundaries = {}
    return re.sub(r"=+\d+==", lambda m: boundaries.setdefault(m.group(0), f"===BOUNDARY-{len(boundaries) + 1}==="),
                  str(text))
