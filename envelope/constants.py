import sys

try:
    import gnupg
except ImportError:
    gnupg = None

smime_import_error = "Cannot import M2Crypto. Run: `sudo apt install swig && pip3 install M2Crypto`"
CRLF = '\r\n'
AUTO = "auto"
PLAIN = "plain"
HTML = "html"
SIMULATION = "simulation"
# We read verbose raw output from underlying GPG program, hence we need the most default locale "C".
# Note that for Python 3.6, "C" fails with non-ASCII characters, "C.UTF-8" worked instead, however as it is difficult
# to determine whether a locale is available on the system, we prefer to stick with "C". #24
# We cannot set as constant whole os.environ dict as it might be changed in the tests.py (settings GNUPG_HOME).
SAFE_LOCALE = "C" if (sys.version_info.major, sys.version_info.minor) > (3, 6) else "C.UTF-8"
