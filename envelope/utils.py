import logging
from io import TextIOBase, BufferedIOBase
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
    if isinstance(v, Iterable) and not isinstance(v, (TextIOBase, BufferedIOBase, str, bytes)):
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
    elif isinstance(message, (TextIOBase, BufferedIOBase)):
        message = message.read()
    elif not isinstance(message, (str, bytes, bool)):
        raise ValueError(
            f"Expected str, bytes, stream or pathlib.Path: {message}")

    if retyped is bytes and isinstance(message, str):
        message = message.encode("utf-8")
    elif retyped is str and isinstance(message, bytes):
        message = message.decode("utf-8")
    return message
