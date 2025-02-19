from email.utils import getaddresses, parseaddr
import logging
from os import environ
import re
import inspect
import sys
from .utils import assure_list

environ['PY3VE_IGNORE_UPDATER'] = '1'
from validate_email import validate_email  # noqa, #17 E402, the package name is py3-validate-email


logger = logging.getLogger(__name__)


def _getaddresses(*args):
    # NOTE Python finally changed the old way of parsing wrong addresses.
    # README should reflect that.
    #
    # We might start using strict=True (default) in the future.
    # The difficult version check is due to #45. Docs show that the parameter was added at 3.13,
    # however older docs show it was at 3.12.6. Mine 3.12.3 has it too. And according to tests,
    # it seems some 3.11.N have it too. It seems to be backported randomly.
    # Remove the check as of Python3.13 being the minimum version.
    # if sys.version_info <= (3, 11) or sys.version_info[:2] == (3, 12) and sys.version_info < (3, 12, 3):
    signature = inspect.signature(getaddresses)
    parameters = signature.parameters

    if 'strict' in parameters:
        return getaddresses(*args, strict=False)
    return getaddresses(*args)


def _parseaddr(*args):
    # See the comment _getaddresses.
    signature = inspect.signature(getaddresses)
    parameters = signature.parameters
    if 'strict' in parameters:
        return parseaddr(*args, strict=False)
    return parseaddr(*args)


class Address(str):
    """
        You can safely access the `self.name` property to access the real name and `self.address` to access the e-mail address.
        Example: Address("John <person@example.com>") -> self.name = "John", self.address = "person@example.com"

        Similarly, there are `self.user` and `self.host` properties.
        Example: -> self.user= "person", self.host = "example.com"

        All properties are guaranteed to be strings.
        Example: a = Address("") → a.name == "", bool(a) is False

        Address objects are equal if their e-mail address are equal. (Their real names might differ.)
        Address object is equal to a string if the string contains its e-mail address or the whole representation.
        Example: "person@example.com" == Address("John <person@example.com>") == "John <person@example.com>"  # True

        Method casefold returns casefolded object, useful for string comparing (whereas it is still equal to the original object).
        Example Address("John <person@example.com>").casefold() -> self.name == "john"

    """

    _name: str
    _address: str
    disguised_address = re.compile(r"([^,;]*@[^,;]*)<(.*?@.*?)>")

    def __new__(cls, displayed_email=None, name=None, address=None):
        if displayed_email:
            v = _parseaddr(cls.remedy(displayed_email))
            name, address = v[0] or name, v[1] or address

        if name:
            displayed_email = f"{name} <{address}>"
        else:
            displayed_email = address

        instance = super().__new__(cls, displayed_email or "")
        instance._name, instance._address = name or "", address or ""
        return instance

    def __eq__(self, other):
        """
        Address objects are equal if their e-mail address are equal. (Their real names might differ.)
        Address object is equal to a string if the string contains its e-mail address or the whole representation.
        Example: "person@EXAMPLE.com" == Address("John <person@example.com>") == "John <person@example.com>"  # True
        """
        s = hash(other.casefold())
        return hash(self) == s or hash(str(self).casefold()) == s

    def casefold(self) -> "Address":
        """ When comparing Addresses, use casefolded version. Important for Address.__eq__
         (if retyped to a string, we could not compare addresses via Address.__hash__)"""
        return Address(str(self).casefold())

    def __hash__(self):
        """ E-mail addresses are case insensitive """
        return hash(self.address.casefold())

    def __repr__(self):
        return self.__str__()

    @property
    def name(self) -> str:
        return self._name

    @property
    def address(self) -> str:
        return self._address

    @property
    def host(self) -> str:
        """ Get the part behind the '@' sign.
            Example: Address("person1@example.com").host == "example.com"
            Example: Envelope().to("person1@example.com").to().host == "example.com"
        """
        try:
            return self._address.split("@")[1]
        except IndexError:
            return ""

    @property
    def user(self) -> str:
        """ Get the part before the '@' sign.
            Example: Address("person1@example.com").user == "person1"
            Example: Envelope().to("person1@example.com").to().user == "person1"
        """
        try:
            return self._address.split("@")[0]
        except IndexError:
            return ""

    def get(self, name: bool = None, address: bool = None) -> str:
        """ Return `name` and/or `address`.
        Example:
            e = (Envelope()
                .to("person1@example.com")
                .to("person1@example.com, John <person2@example.com>")
                .to(["person3@example.com"]))

            [str(x) for x in e.to()]                # ["person1@example.com", "John <person2@example.com>", "person3@example.com"]
            [x.get(address=False) for x in e.to()]  # ["", "John", ""]
            [x.get(name=True) for x in e.to()]      # ["person1@example.com", "John", "person3@example.com"]
                                                    # return an address if no name given
            [x.get(address=True) for x in e.to()]   # ["person1@example.com", "person2@example.com", "person3@example.com"]
                                                    # addresses only
        """

        if not self:
            return ""
        if name is None and address is False:
            name = True
        elif name is False and address is None:
            address = True
        elif name is None and address is None:
            name = address = True

        if name and address:
            return str(self)
        if name and not address:
            s = self.name
            # 'John <person@example.com>' -> 'John'
            # 'person@example.com>' -> '' (address=False) or 'John' (name=True)
            if not s and address is not False:
                return self.address
            return s
        if not name and address:
            return self.address
        raise TypeError(
            "Specify at least one of the `name` and `address` arguments.")

    @classmethod
    def parse(cls, email_or_list, single=False, allow_false=False):
        # .from_(False), .sender(False)
        if allow_false and email_or_list is False:
            return False

        addrs = _getaddresses(cls.remedy(x) for x in assure_list(email_or_list))
        addresses = [Address(name=real_name, address=address)
                     for real_name, address in addrs if not (real_name == address == "")]
        if single:
            if len(addresses) != 1:
                raise ValueError(
                    f"Single e-mail address expected: {email_or_list}")
            return addresses[0]
        # if len(addresses) == 0:
        #     raise ValueError(f"E-mail address cannot be parsed: {email_or_list}")
        # if len(addresses) == 0:
        #     return email_or_list
        return addresses

    @classmethod
    def remedy(cls, displayed_email):
        def remedy(s):
            """ Disguised addresses like "person@example.com <person@example2.com>" are wrongly
            parsed as two distinguish addresses with getaddresses. Rename the at-sign in the display name
            to "person--AT--example.com <person@example2.com>" so that the result of getaddresses is less wrong.
            """

            """
            What happens when the string have more addresses?
            It also needs to get the address from string like "person@example.com, <person@example.com>" so we need to
            take care of the comma and semicolon as well.
            """
            if s.group(1).strip() == s.group(2).strip():
                # Display name is the same as the e-mail in angle brackets
                # Ex: "person@example.com <person@example.com>"
                # Do not replace @-sign, rather suppress the name, returning just the address.
                return s.group(2)

            return (s.group(1).replace("@", "--AT--") + f"<{s.group(2)}>")
        return cls.disguised_address.sub(remedy, displayed_email)

    def is_valid(self, check_mx=False):
        if not validate_email(self.address, check_dns=False, check_smtp=False, check_blacklist=False):
            logger.warning(f"Address format invalid: '{self}'")
            return False
        elif check_mx and print(f"Verifying {self}...") and not validate_email(self.address, check_dns=True):
            logger.warning(f"MX check failed for: '{self}'")
            return False
        return True
