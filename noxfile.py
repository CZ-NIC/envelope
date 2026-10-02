""" Test sessions. Run all: `nox`, one: `nox -s tests-3.12`, list: `nox -l`. """
import nox

nox.options.default_venv_backend = "venv"
nox.options.sessions = ["tests", "magic"]

PYTHONS = ["3.10", "3.11", "3.12", "3.13"]
PYPROJECT = nox.project.load_toml("pyproject.toml")
TEST_DEPS = nox.project.dependency_groups(PYPROJECT, "test")


@nox.session(python=PYTHONS)
def tests(session: nox.Session):
    """ The whole suite. """
    session.install("-e", ".", *TEST_DEPS)
    session.run("pytest", "-n", "auto", *session.posargs)


@nox.session
@nox.parametrize("backend", ["python-magic", "file-magic", "none"])
def magic(session: nox.Session, backend: str):
    """ We support both libmagic bindings: python-magic (default dependency) and file-magic.
    Without either of them, the libmagic test must fail. """
    session.install("-e", ".", "pytest")
    if backend != "python-magic":
        session.run("pip", "uninstall", "-y", "python-magic")
    if backend == "file-magic":
        session.install("file-magic")
    session.run("pytest", "tests/test_mime.py::test_libmagic", "-p", "no:cacheprovider",
                success_codes=[1] if backend == "none" else [0])
