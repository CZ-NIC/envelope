import logging
from email.generator import BytesGenerator, Generator
from email.message import Message, MIMEPart
from io import BytesIO, IOBase, StringIO
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

try:
    import magic
except ImportError as e:
    magic = e

if TYPE_CHECKING:
    from .envelope import Envelope

logger = logging.getLogger(__name__)
Fetched = str | bytes | None


class _SignedPreservingGenerator(Generator):
    """ Flatten multipart/signed like any other multipart.

    The stdlib disables header folding inside multipart/signed, so a long header (ex: attachment file name
    longer than 34 chars) gets output differently than it was when the GPG signature was computed and the signature
    breaks. See #19 and https://github.com/python/cpython/issues/99533
    (Used instead of patching `Generator` globally, which would affect all the threads.)
    """
    _handle_multipart_signed = Generator._handle_multipart


class _SignedPreservingBytesGenerator(BytesGenerator):
    _handle_multipart_signed = Generator._handle_multipart


def message_as_string(msg) -> str:
    """ Same as `str(msg)`, using the `_SignedPreservingGenerator`. Non-Message objects are just cast to str. """
    if not isinstance(msg, Message):
        return str(msg)
    if isinstance(msg, MIMEPart):  # EmailMessage
        policy = msg.policy.clone(utf8=True)
        maxheaderlen = policy.max_line_length
    else:
        policy = msg.policy
        maxheaderlen = 0
    fp = StringIO()
    _SignedPreservingGenerator(fp, mangle_from_=False, maxheaderlen=maxheaderlen, policy=policy).flatten(msg)
    return fp.getvalue()


def message_as_smtp_bytes(msg: Message, policy=None) -> bytes:
    """ Same as `smtplib.SMTP.send_message` flattens the message, using the `_SignedPreservingBytesGenerator`. """
    with BytesIO() as fp:
        _SignedPreservingBytesGenerator(fp, policy=policy).flatten(msg, linesep="\r\n")
        return fp.getvalue()


class AutoSubmittedHeader:
    """  "auto-replied": direct response to another message by an automatic process """

    def __init__(self, parent: 'Envelope'):
        self._parent = parent

    def __call__(self, val="auto-replied"):
        """
        :param val: "auto-replied": direct response to another message by an automatic process
        """
        self._parent.header("Auto-Submitted", val, replace=True)
        return self._parent

    def no(self):
        """ message was originated by a human """
        return self("no")

    def auto_replied(self):
        """ direct response to another message by an automatic process """
        return self()

    def auto_generated(self):
        """ automatic (often periodic) processes (such as UNIX "cron jobs") which are not direct responses to other messages """
        return self("auto-generated")


def is_gpg_importable_key(key):
    """ Check if the variable contains the key contents itself
     (it may contain a fingerprint or an e-mail address too) """
    return len(key) >= 512  # 512 is the smallest possible GPG key


def get_mimetype(data: bytes = None, path: Path = None):
    """ We support both python-magic and file-magic library, any of them can be on the system. #25
        Their funcionality is the same, their API differs.
    """
    if isinstance(magic, ImportError):  # user has to install libmagic
        raise magic
    if hasattr(magic.Magic, "from_file"):  # this is python-magic
        if data:
            return magic.Magic(mime=True).from_buffer(data)
        if path:
            return magic.Magic(mime=True).from_file(str(path))
    else:  # this is file-magic
        if data:
            return magic.detect_from_content(data).mime_type
        if path:
            return magic.detect_from_filename(str(path)).mime_type


def is_safe_argv_value(s: str) -> bool:
    """ Check a string is safe to pass as a single subprocess argv value derived from
    untrusted (e.g. parsed e-mail) content: not empty, does not start with "-" (which some
    CLI parsers could otherwise mistake for a new option) and contains no whitespace or
    control characters. """
    if not s or s[0] == "-":
        return False
    return all(c.isprintable() and not c.isspace() for c in s)


def assure_list(v):
    """ Accepts object and returns list.
    If object is tuple, generator, set, frozenset, it's converted to a list.
    If object is not a list, it's appended to a list.
    If None, returns an empty list.
        "test" → ["test"]
        (5,1) → [5,1]
        ["test", "foo"] → ["test", "foo"]
    """
    if v is None:
        return []
    if isinstance(v, Iterable) and not isinstance(v, (IOBase, str, bytes)):
        return list(v)
    return [v]


def assure_fetched(message, retyped=None) -> Fetched:
    """ Accepts object, returns its string or bytes.
    If object is
        * str or bytes, we consider this is the file contents
        * Path, we load the file
        * stream, we read it
        * bool or none, it is returned as is.
    :type message: object to be converted
    :type retyped: * str or bytes to assure str/bytes are returned.
                   * None does not perform retyping.
    """
    if message is None:
        return None
    elif isinstance(message, Path):
        message = message.read_bytes()
    elif isinstance(message, IOBase):
        message = message.read()
    elif not isinstance(message, (str, bytes, bool)):
        raise ValueError(
            f"Expected str, bytes, stream or pathlib.Path: {message}")

    if retyped is bytes and isinstance(message, str):
        message = message.encode("utf-8")
    elif retyped is str and isinstance(message, bytes):
        message = message.decode("utf-8")
    return message
