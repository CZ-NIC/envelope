import logging
from typing import Optional, Tuple, Union, Type
logger = logging.getLogger(__name__)


class _Message:
    auto: Optional[bytes] = None
    plain: Optional[bytes] = None
    html: Optional[bytes] = None
    # you may specify e-mail boundary used when multiple alternatives present
    boundary: Optional[str] = None

    def _decode(self, val, mime_alternative):
        try:
            val = val.decode()
        except UnicodeDecodeError as e:
            logger.warning(f"Cannot decode the message correctly,"
                           f" {mime_alternative} alternative bytes are not in Unicode.")
            val = str(val)
        return val

    def get(self, type_: Union[Type[bytes], Type[str]] = bytes) -> Tuple[Union[bytes, str, None], Union[bytes, str, None]]:
        """
        :param type_: Set to str if we should return str instead of bytes.
         Note it raises a warning if bytes were not in Unicode.
        :return (plain, html) tuple Data assured to be fetched. Raises if there is anything left in `auto`.
        """
        i = iter((self.auto,))
        plain, html = self.plain or next(i, None), self.html or next(i, None)
        if next(i, False):
            raise ValueError("Specified all of message alternative=plain, alternative=html and alternative=auto,"
                             " choose only two.")

        # XX As of Python3.10 replace with longer but more readable:
        # plain, html = self.plain, self.html
        # if self.auto:
            # match bool(plain), bool(html):
            #     case False, _:
            #         plain = auto
            #     case _, False:
            #         html = auto
            #     case _:
        #             raise ValueError("Specified all of message alternative=plain, alternative=html and alternative=auto,"
        #                      " choose only two.")

        if type_ is str:
            if plain:
                plain = self._decode(plain, "plain")
            if html:
                html = self._decode(html, "html")
        return plain, html

    def is_empty(self):
        return tuple(self.get()) == (None, None)

    def __str__(self):
        text, html = self.get(str)
        if text and html:
            return " ".join(("(text/plain)", text, "(text/html)", html))
        else:
            return text or html
