""" Message contents: body text, Subject, Date, MIME subtype, List-Unsubscribe and attachments. Mixed into Envelope. """
import binascii
import logging
import re
from base64 import b64decode
from pathlib import Path
from quopri import decodestring
from types import GeneratorType
from typing import IO, TYPE_CHECKING, Any, Literal, Optional, Union, overload

from .attachment import Attachment
from .constants import AUTO, HTML, PLAIN
from .utils import assure_fetched, assure_list

if TYPE_CHECKING:
    from .envelope import Envelope

logger = logging.getLogger("envelope.envelope")  # keep the original logger name


class _ContentMixin:

    def body(self, text=None, *, path=None):
        """ An alias of .message """
        return self.message(text=text, path=path)

    def text(self, text=None, *, path=None):
        """ An alias of .message """
        return self.message(text=text, path=path)

    @overload
    def message(self, text: None = None, *, path: None = None, alternative: str = AUTO, boundary: Optional[str] = None) -> str: ...

    @overload
    def message(self, text: Union[str, bytes, Path, IO[Any]], *, path: Union[str, Path, None] = None, alternative: str = AUTO, boundary: Optional[str] = None) -> "Envelope": ...

    @overload
    def message(self, text: None = None, *, path: Union[str, Path], alternative: str = AUTO, boundary: Optional[str] = None) -> "Envelope": ...

    def message(self, text=None, *, path=None, alternative=AUTO, boundary=None) -> Union["Envelope", str]:
        """
        Message to be ciphered / e-mail body text.
        :param text: Any attainable contents.
        :param path: Path to the file.
        :param alternative: "auto", "html", "plain" You may specify e-mail text alternative.
         Some e-mail readers prefer to display plain text version over HTML.
          By default, we try to determine content type automatically (see *mime*).
        :param boundary: When specifying alternative, you may set e-mail boundary if you do not wish a random one to be created.

        Example:
            print(Envelope().message("He<b>llo</b>").message("Hello", alternative="plain"))

            # (output shortened)
            # Content-Type: multipart/alternative;
            #  boundary="===============0590677381100492396=="
            #
            # --===============0590677381100492396==
            # Content-Type: text/plain; charset="utf-8"
            # Hello
            #
            # --===============0590677381100492396==
            # Content-Type: text/html; charset="utf-8"
            # He<b>llo</b>

        :return: Envelope if `text` or `path` is set
            otherwise return anything that has been inserted to the .message() before as `str`
        """
        # XX make preview default over send(0) when no action is given?
        if boundary is not None:
            self._message.boundary = boundary
        if alternative not in (AUTO, PLAIN, HTML):
            raise ValueError(f"Invalid alternative {alternative} for message,"
                             f" choose one of the: {AUTO}, {PLAIN}, {HTML}")
        if text is path is None:
            # reading value
            b = getattr(self._message, alternative)
            if not b and alternative == AUTO:  # prefer reading HTML over plain text if alternative set
                b = self._message.html or self._message.plain

            # When loading an EML, Content-Type and Content-Transfer-Encoding get wiped off and the message is decoded.
            # However, the user can define the headers explicitly.
            # In that case we expect the message is already inserted encoded. (However, if it not, we do our best.)

            # The user can define the Content-Type
            content_type = self._headers.get("Content-Type")
            m = re.search("charset=(.*)", content_type, re.IGNORECASE) if content_type else None
            charset = m[1] if m else "utf-8"

            # Content-Transfer-Encoding might be active
            transfer = self._headers.get("Content-Transfer-Encoding")
            if transfer == "base64":
                try:
                    return b64decode(b).decode(charset)
                except binascii.Error:
                    pass  # the user specified Content-Transfer-Encoding but left the message unencoded
                except UnicodeDecodeError:
                    raise TypeError(f"Cannot base64-decode the message: {b}")
            elif transfer == "quoted-printable":
                try:
                    return decodestring(b).decode(charset)
                except ValueError:
                    pass  # the user specified Content-Transfer-Encoding but left the message unencoded

            if b is None:
                return ""
            try:
                return b.decode(charset)
            except UnicodeError:
                raise ValueError(f"Cannot decode the message correctly, it is not in Unicode. {b}")

        # write value
        if path:
            text = Path(path)

        setattr(self._message, alternative, assure_fetched(text, bytes))
        return self

    def date(self, date):
        """
        Specify Date header. If not used, Date will be added automatically.
        :param date: str|False If False, the Date header will not be added automatically.
        """
        if date is False:
            if "Date" in self._headers:  # removes date header
                del self._headers["Date"]
            self._ignore_date = True
        else:
            self._ignore_date = False
            self.header("Date", date)
        return self

    @overload
    def subject(self, subject: None = None, encrypted: None = None) -> str: ...

    @overload
    def subject(self, subject: str, encrypted: Union[str, bool, None] = None) -> "Envelope": ...

    @overload
    def subject(self, subject: None = None, *, encrypted: Union[str, bool]) -> "Envelope": ...

    @overload
    def subject(self, subject: None, encrypted: Union[str, bool]) -> "Envelope": ...

    def subject(self, subject=None, encrypted: Optional[Union[str, bool]] = None) -> Union["Envelope", str]:
        """ Get or set the message subject
        :param subject: Subject text.
        :param encrypted: Text used instead of the real protected subject while PGP encrypting. False to not encrypt.
        :return If neither parameter specified, current subject returned, otherwise return self.
        """
        if subject is None and encrypted is None:
            return str(self._subject or "")
        if subject is not None:
            self._subject: str = subject
        if encrypted is not None:
            self._subject_encrypted = encrypted
        return self

    def mime(self, subtype=AUTO, nl2br: Literal["auto"] | bool = AUTO):
        """
        Ignored if `Content-Type` header put to the message.
        @type subtype: str Set contents mime subtype: "auto" (default), "html" or "plain" for plain text.
        @param nl2br: True: envelope will append `<br>` to every line break in the HTML message.
                      "auto": line breaks are changed only if there is no `<br` or `<p` in the HTML message,
        """
        self._mime = subtype
        self._nl2br = nl2br
        return self

    def list_unsubscribe(self, uri=None, one_click=False, *, web=None, email=None):
        """ The header will not be encrypted with GPG nor S/MIME.
        :param uri: Web or e-mail address.
            We try to determine whether this is e-mail and prepend brackets and 'https:'/'mailto:' if needed
            Ex: "me@example.com?subject=unsubscribe", "example.com/unsubscribe", "<https://example.com/unsubscribe>"
        :param one_click: If True, rfc8058 List-Unsubscribe-Post header is added.
            This says user can unsubscribe with a single click that is realized by a POST request
            in order to prevent e-mail scanner to access the unsubscribe page by mistake. A 'https' url must be present.
        :param web: URL. Ex: "https://example.com/unsubscribe"
            Without protocol, `https://` is prepended, "example.com/unsubscribe" -> "https://example.com/unsubscribe"
        :param email: E-mail address. Ex: "me@example.com", "mailto:me@example.com"
        :return: self
        """

        elements = []
        if "List-Unsubscribe" in self._headers:
            elements.extend(self._headers["List-Unsubscribe"].split(","))

        if one_click:
            self.header("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")
            if uri and not web:  # we are sure this is web because one-click header does not go with an e-mail
                web = uri
                uri = None

        if uri.startswith("<"):
            elements.append(uri)
        elif uri.startswith(("http:", "https:", "mailto:", "//")):
            elements.append(f"<{uri}>")
        elif "@" in uri:
            elements.append(f"<mailto:{uri}>")
        else:
            elements.append(f"<https://{uri}>")

        if web:
            if uri.startswith(("http:", "https:", "//")):
                elements.append(f"<{web}>")
            else:
                elements.append(f"<https://{web}>")

        if email:
            if uri.startswith("mailto:"):
                elements.append(f"<{email}>")
            else:
                elements.append(f"<mailto:{email}>")

        self.header("List-Unsubscribe", ", ".join(elements), replace=True)
        return self

    def attach(self, attachment=None, mimetype=None, name=None, inline=None, *, path=None):
        """

        :type attachment: Any attainable contents that should be added as an attachment or their list.
                The list may contain tuples: `any_attainable_contents [,mime type] [,file name] [, True for inline]`.
        :param mimetype: Mime type OR file name of the attachment.
        :param name: Mime type OR file name of the attachment.
        :param path: Path to the file that should be attached.
        :param inline: Set parameter content-id (CID) so that we may reference image from within HTML message body.
                       * str: The attachment will get this CID.
                       * True: Filename or attachment or path file name is set as CID.
                       Example:
                           .attach("file.jpg", inline=True) -> <img src='cid:file.jpg' />
                           .attach(b"GIF89a\x03\x00\x03...", filename="file.gif", inline=True) -> <img src='cid:file.gif' />
                           .attach("file.jpg", inline="foo") -> <img src='cid:foo' />
        """
        if isinstance(attachment, (tuple, list, GeneratorType, set, frozenset)):
            # putting all these types normally work, however, only list is acknowledged in the documentation for now
            if path or mimetype or name:
                raise ValueError("Cannot specify both path, mimetype or name and put a list in attachment.")
        else:
            if path:
                attachment = Path(path)
            attachment = [(attachment, mimetype, name, inline)]
        self._attachments += [Attachment(o) for o in assure_list(attachment)]
        return self

    @overload
    def attachments(self, name: None = None, inline: Optional[bool] = None) -> list[Attachment]: ...

    @overload
    def attachments(self, name: str, inline: Optional[bool] = None) -> Union[Attachment, Literal[False]]: ...

    def attachments(self, name=None, inline=None) -> Union[Attachment, list[Attachment], bool]:
        """ Access the attachments.
            XX make available from CLI too
                --attachments(-inline)(-enclosed) [name]
            :type name: str Set the name of the only desired attachment to be returned.
            :type inline: bool Filter inline/enclosed attachments only.
            :return Attachment or False when a name is set, otherwise list of all the attachments.
        """
        attachments = [a for a in self._attachments if bool(a.inline) == inline] if inline is not None \
            else self._attachments

        if name is not None:
            for a in attachments:
                if a.name == name:
                    return a
            else:
                return False
        return attachments
