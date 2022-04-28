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
