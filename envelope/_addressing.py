"""Address-related setters/getters (`to`, `cc`, `bcc`, `reply_to`, `from_`, `from_addr`, `recipients`) of `Envelope`.
Mixin: shares one `self` with `Envelope`; nothing here is meant to be used standalone.
"""
import logging
from typing import Literal, Union, Iterable, overload, TYPE_CHECKING

from .address import Address
from .utils import assure_list

if TYPE_CHECKING:
    from .envelope import Envelope

logger = logging.getLogger("envelope.envelope")  # same logger name as before the split


class _AddressingMixin:
    @staticmethod
    def _parse_addresses(registry, email_or_more):
        addresses = assure_list(email_or_more)
        if any(not x for x in addresses):
            registry.clear()
        addresses = [x for x in addresses if x]  # filter out possible "" or False
        if addresses:
            # Split addresses by both commas and semicolons
            split_addresses = []
            for address in addresses:
                split_addresses.extend(address.replace(';', ',').split(','))
            # remove empty and whitespace-only strings
            split_addresses = [x.strip() for x in split_addresses if x.strip()]
            registry += (a for a in Address.parse(split_addresses) if a not in registry)

    @overload
    def to(self, email_or_more: None = None) -> list[Address]: ...

    @overload
    def to(self, email_or_more: Union[str, Address, Iterable[Union[str, Address]]]) -> "Envelope": ...

    def to(self, email_or_more=None) -> Union["Envelope", list[Address]]:
        """ Multiple addresses may be given in a string, delimited by comma (or semicolon).
         (The same is valid for `to`, `cc`, `bcc` and `reply-to`.)

            :param email_or_more: str|Tuple[str]|list[str]|Generator[str]|Set[str]|Frozenset[str]
             Set e-mail address/es. If None, we are reading.
            return: Envelope if `email_or_more` set or list[Address] if not set
        """
        if email_or_more is None:
            return self._to
        self._parse_addresses(self._to, email_or_more)
        return self

    @overload
    def cc(self, email_or_more: None = None) -> list[Address]: ...

    @overload
    def cc(self, email_or_more: Union[str, Address, Iterable[Union[str, Address]]]) -> "Envelope": ...

    def cc(self, email_or_more=None) -> Union["Envelope", list[Address]]:
        if email_or_more is None:
            return self._cc
        self._parse_addresses(self._cc, email_or_more)
        return self

    @overload
    def bcc(self, email_or_more: None = None) -> list[Address]: ...

    @overload
    def bcc(self, email_or_more: Union[str, Address, Iterable[Union[str, Address]]]) -> "Envelope": ...

    def bcc(self, email_or_more=None) -> Union["Envelope", list[Address]]:
        if email_or_more is None:
            return self._bcc
        self._parse_addresses(self._bcc, email_or_more)
        return self

    @overload
    def reply_to(self, email_or_more: None = None) -> list[Address]: ...

    @overload
    def reply_to(self, email_or_more: Union[str, Address, Iterable[Union[str, Address]]]) -> "Envelope": ...

    def reply_to(self, email_or_more=None) -> Union["Envelope", list[Address]]:
        if email_or_more is None:
            return self._reply_to
        self._parse_addresses(self._reply_to, email_or_more)
        return self

    @overload
    def from_(self, email: None = None) -> Address: ...

    @overload
    def from_(self, email: Union[str, Address, Literal[False]]) -> "Envelope": ...

    def from_(self, email=None) -> Union["Envelope", Address]:
        """ Set the `From` header. If None, current `From` returned. """
        if email is None:
            return self._from or Address()
        self._from = Address.parse(email, single=True, allow_false=True)
        return self

    @overload
    def from_addr(self, email: None = None) -> Address: ...

    @overload
    def from_addr(self, email: Union[str, Address, Literal[False]]) -> "Envelope": ...

    def from_addr(self, email=None) -> Union["Envelope", Address]:
        if email is None:
            return self._from_addr or Address()
        self._from_addr = Address.parse(email, single=True)
        return self

    @overload
    def recipients(self, *, clear: Literal[False] = False) -> set[Address]: ...

    @overload
    def recipients(self, *, clear: Literal[True]) -> "Envelope": ...

    @overload
    def recipients(self, *, clear: bool) -> Union[set[Address], 'Envelope']: ...

    def recipients(self, *, clear=False) -> Union[set[Address], 'Envelope']:
        """ Return set of all recipients – To, Cc, Bcc
            :param: clear If true, all To, Cc and Bcc recipients are removed and the object is returned.

            Envelope()
                .to("person1@example.com")
                .to("person1@example.com, John <person2@example.com>")
                .to(["person3@example.com"])
                .recipients()  # ["person1@example.com", "John <person2@example.com>", "person3@example.com"]
        """
        if clear:
            self._to.clear()
            self._cc.clear()
            self._bcc.clear()
            return self
        return {x for x in set(self._to + self._cc + self._bcc)}
