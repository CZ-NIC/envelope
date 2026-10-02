import io
import logging
import shutil
import socket
import subprocess
import sys
import traceback
from pathlib import Path

import pytest

from envelope.__main__ import main
from helpers import EML, GPG_RING


def _kill_gpg_agent(home: Path):
    subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True)


@pytest.fixture(scope="session", autouse=True)
def gpg_home(tmp_path_factory) -> Path:
    """ A throwaway copy of the testing keyring, also set as GNUPGHOME for the whole session.
    Tests may import keys into it without polluting tests/fixtures/. """
    home = tmp_path_factory.mktemp("gpg") / "ring"
    shutil.copytree(GPG_RING, home, ignore=shutil.ignore_patterns("random_seed", "S.*"))
    home.chmod(0o700)
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("GNUPGHOME", str(home))
        yield home
    _kill_gpg_agent(home)


@pytest.fixture
def empty_gpg_home_factory(tmp_path_factory):
    """ Factory producing new empty keyrings: `ring = empty_gpg_home_factory()`, call it as many times as needed. """
    homes = []

    def make() -> Path:
        home = tmp_path_factory.mktemp("gpg-empty")
        home.chmod(0o700)
        homes.append(home)
        return home

    yield make
    for home in homes:
        _kill_gpg_agent(home)


@pytest.fixture
def cli(monkeypatch, tmp_path):
    """ Run the envelope CLI in-process, like `python3 -m envelope ARGS < stdin`.

    Usage: `cli("--subject", "hello", stdin="message")`. Returns the stdout + stderr + logged warnings,
    with an uncaught exception's traceback appended (just like a subprocess would print it).
    :param stdin: str/bytes/Path piped to the program; defaults to the sample tests/fixtures/eml/mail.eml.
    :param env: Environment variables to set for the run.
    :param decode: If False, return raw bytes.
    """
    counter = 0

    def run(*args, stdin: str | bytes | Path = EML, env: dict | None = None, decode=True) -> str | bytes:
        nonlocal counter
        counter += 1
        if isinstance(stdin, Path):
            stdin = stdin.read_bytes()
        elif isinstance(stdin, str):
            stdin = stdin.encode()
        stdin_file = tmp_path / f"cli-stdin-{counter}"
        stdin_file.write_bytes(stdin)

        buffer = io.BytesIO()
        out = io.TextIOWrapper(buffer, encoding="utf-8", write_through=True)
        handler = logging.StreamHandler(out)
        handler.setLevel(logging.WARNING)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("envelope")

        with monkeypatch.context() as m, stdin_file.open() as stdin_stream:
            m.setattr(sys, "argv", ["envelope", *map(str, args)])
            m.setattr(sys, "stdin", stdin_stream)
            m.setattr(sys, "stdout", out)
            m.setattr(sys, "stderr", out)
            for key, value in (env or {}).items():
                m.setenv(key, str(value))
            logger.addHandler(handler)
            try:
                main()
            except SystemExit:
                pass
            except Exception:
                traceback.print_exc(file=out)
            finally:
                logger.removeHandler(handler)
                out.flush()

        result = buffer.getvalue()
        return result.decode().rstrip() if decode else result

    return run


@pytest.fixture
def smtp_server(monkeypatch):
    """ A real local SMTP server (aiosmtpd) on a free port. Received messages are in `smtp_server.messages`
    as aiosmtpd Envelope objects (`.mail_from`, `.rcpt_tos`, `.content`). Use `.smtp("localhost", smtp_server.port)`. """
    controller_module = pytest.importorskip("aiosmtpd.controller")
    from envelope.smtp_handler import SMTPHandler

    class Handler:
        def __init__(self):
            self.messages = []

        async def handle_DATA(self, server, session, envelope):
            self.messages.append(envelope)
            return "250 Message accepted for delivery"

    with socket.socket() as s:
        s.bind(("localhost", 0))
        port = s.getsockname()[1]

    handler = Handler()
    controller = controller_module.Controller(handler, hostname="localhost", port=port)
    controller.start()
    handler.port = port
    # isolate the class-level connection cache so that connections do not leak between tests
    monkeypatch.setattr(SMTPHandler, "_instances", {})
    yield handler
    SMTPHandler.quit_all()
    controller.stop()
