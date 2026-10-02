import sys

import pytest

from envelope import Envelope
from envelope.address import Address, _parseaddr, _getaddresses
from helpers import (assert_lines, CHARSET, EML, IDENTITY_1, IDENTITY_2, IDENTITY_3, MESSAGE)

ID1 = "identity-1@example.com"
ID2 = "identity-2@example.com"


@pytest.mark.parametrize("envelope", [
    lambda: Envelope(MESSAGE).header("sender", ID1),
    lambda: Envelope(MESSAGE, headers=[("sender", ID1)]),
], ids=["header-method", "headers-kwarg"])
def test_sender_header_is_not_from(envelope):
    assert_lines(envelope(), f"sender: {ID1}", absent=f"From: {ID1}")


@pytest.mark.parametrize("envelope", [
    lambda: Envelope(MESSAGE, from_=ID1),
    lambda: Envelope(MESSAGE).from_(ID1),
], ids=["kwarg", "method"])
def test_from_is_not_sender(envelope):
    assert_lines(envelope(), f"From: {ID1}", absent=f"Sender: {ID1}")


@pytest.mark.parametrize("envelope", [
    lambda: Envelope(MESSAGE).from_(ID1).header("Sender", ID2),
    lambda: Envelope(MESSAGE).header("Sender", ID2).from_(ID1),
], ids=["from-first", "sender-first"])
def test_from_and_sender_together(envelope):
    assert_lines(envelope(), f"From: {ID1}", f"Sender: {ID2}")


@pytest.mark.cli
def test_from_addr(cli):
    mail1 = "envelope-from@example.com"
    mail2 = "header-from@example.com"
    e = Envelope(MESSAGE).from_addr(mail1).from_(mail2)
    assert e.from_addr() == mail1
    assert e.from_() == mail2
    assert "Have not been sent from " + mail1 in str(e.send(False))
    e = Envelope(MESSAGE).from_(mail2)
    assert "Have not been sent from " + mail2 in str(e.send(False))
    e = Envelope(MESSAGE, from_addr=mail1).from_(mail2)
    assert "Have not been sent from " + mail1 in str(e.send(False))
    assert "Have not been sent from " + mail1 in cli("--from-addr", mail1, "--send", "0", stdin=EML)


def test_address_basics():
    e = Envelope.load(path=EML)
    assert len(e.to()) == 1
    contact = e.to()[0]
    full = "Person <person@example.com>"
    assert contact == full
    assert contact == "person@example.com"
    assert contact.address == "person@example.com"
    assert contact.name == "Person"
    assert contact == "PERSON@examPLE.com"
    assert contact == Address("another name <PERSON@examPLE.com>")
    assert contact != "person2@example.com"
    assert contact != Address("another name <person2@example.com>")

    # host property
    assert contact.host == "example.com"
    assert contact.host != "@example.com"

    # user property
    assert contact.user == "person"
    assert contact.user != "PERSON"

    assert contact

    # joining
    assert ", ".join((contact, contact)) == f"{full}, {full}"

    # casefold method
    c = contact.casefold()
    assert c == contact
    assert c is not contact
    assert c.name == "person"
    assert c.name != contact.name


def test_empty_address_is_typed():
    """ Address is correctly typed, empty properties returns string """
    empty = Address()
    assert empty == Address("")
    assert str(empty.user) == ""
    assert str(empty.host) == ""
    assert type(empty.address) is str
    assert type(empty.name) is str
    assert type(empty) is Address
    assert not empty


# These checks represent the email.utils behaviour that is considered buggy.
# If any of them fails, it's a good message the underlying Python libraries are better and we may stop remedying.
# https://github.com/python/cpython/issues/40889#issuecomment-1094001067
@pytest.mark.skipif(sys.version_info < (3, 11), reason="stdlib address parsing differs before Python 3.11")
def test_disguised_addresses_stdlib_behaviour():
    """ Malware actors use at-sign at the addresses to disguise the real e-mail.

    Python standard library has troubles to parse well-formed but exotic addresses. """
    disguise_addr = "first@example.cz <second@example.com>"
    same = "person@example.com <person@example.com>"
    assert _parseaddr(disguise_addr) == ('', 'first@example.cz')
    assert _getaddresses([disguise_addr]) == [('', 'first@example.cz'), ('', 'second@example.com')]
    assert _getaddresses([same]) == [('', 'person@example.com'), ('', 'person@example.com')]


@pytest.mark.skipif(sys.version_info < (3, 11), reason="stdlib address parsing differs before Python 3.11")
def test_disguised_addresses_envelope_is_better():
    """ For the same input as the stdlib gets wrong, Envelope receives better results. """
    disguise_addr = "first@example.cz <second@example.com>"
    same = "person@example.com <person@example.com>"
    disguised = Address(name='first@example.cz', address='second@example.com')
    assert Address(disguise_addr) == disguised
    assert Address.parse(disguise_addr, single=True) == disguised
    assert Address.parse(disguise_addr)[0] == disguised
    person = Address(address='person@example.com')
    assert Address(same) == person
    assert Address.parse(same)[0] == person
    assert Address.parse(same, single=True) == person


# (input, (name, address) of Address(input), [(name, address), ...] of Address.parse(input))
DISGUISED_EXAMPLES = [
    ("person@example.com <person@example.com>",  # the same
     ("", "person@example.com"),
     [("", "person@example.com")]),
    ("person@example.com <person@example2.com>",  # differs, the name hiding the address
     ("person--AT--example.com", "person@example2.com"),
     [("person--AT--example.com", "person@example2.com")]),
    ("pers'one'@'ample.com <a@example.com>",  # single address
     ("pers'one'--AT--'ample.com", "a@example.com"),
     [("pers'one'--AT--'ample.com", "a@example.com")]),
    ("pers'one'@'ample.com, <a@example.com>",  # two addresses
     ("", "pers'one'@'ample.com"),
     [("", "pers'one'@'ample.com"), ("", "a@example.com")]),
    ("alone@example.com",
     ("", "alone@example.com"),
     [("", "alone@example.com")]),
    ("John Smith <john.smith@example.com>",
     ("John Smith", "john.smith@example.com"),
     [("John Smith", "john.smith@example.com")]),
    # a lot of addresses, different delimiters
    ('User ((nested comment))<foo@bar.com> example@example.com ; test@example.com , hello <another@dom.com>',
     ("User (nested comment)", "foo@bar.com"),
     [("User (nested comment)", "foo@bar.com"), ("", "example@example.com"), ("", "test@example.com"),
      ("hello", "another@dom.com")]),
    # one of them is disguised
    ('User ((nested comment))<foo@bar.com> example@example.com ; test@example.com;hello<another@dom.cz> , '
     'ugly@example.com <another@example.com>',
     ("User (nested comment)", "foo@bar.com"),
     [("User (nested comment)", "foo@bar.com"), ("", "example@example.com"), ("", "test@example.com"),
      ("hello", "another@dom.cz"), ("ugly--AT--example.com", "another@example.com")]),
    # three of them are disguised
    ('ug@ly3@example.com <another3@example.com> ,ugly2@example.com <another2@example.com> , '
     'ugly@example.com <another@example.com>',
     ("ug--AT--ly3--AT--example.com", "another3@example.com"),
     [("ug--AT--ly3--AT--example.com", "another3@example.com"), ("ugly2--AT--example.com", "another2@example.com"),
      ("ugly--AT--example.com", "another@example.com")]),
]
DISGUISED_IDS = ["same", "name-hides-address", "single-quoted", "two-addresses", "alone", "john-smith",
                 "many-delimiters", "one-disguised", "three-disguised"]


@pytest.mark.skipif(sys.version_info < (3, 11), reason="stdlib address parsing differs before Python 3.11")
@pytest.mark.parametrize(("text", "single", "multiple"), DISGUISED_EXAMPLES, ids=DISGUISED_IDS)
def test_disguised_addresses_examples(text, single, multiple):
    assert Address(text) == Address(name=single[0], address=single[1])
    assert Address.parse(text) == [Address(name=name, address=addr) for name, addr in multiple]


# Parsing addresses is exactly the same as in the standard email.utils library, so we take its original test cases.
# https://github.com/python/cpython/blob/main/Lib/test/test_email/test_email.py
@pytest.mark.skipif(sys.version_info < (3, 11), reason="stdlib address parsing differs before Python 3.11")
@pytest.mark.parametrize(("addresses", "models"), [
    (['aperson@dom.ain (Al Person)', 'Bud Person <bperson@dom.ain>'],
     [('Al Person', 'aperson@dom.ain'), ('Bud Person', 'bperson@dom.ain')]),
    (['foo: ;'], [('', '')]),
    (['[]*-- =~$'], [('', ''), ('', ''), ('', '*--')]),
    (['foo: ;', '"Jason R. Mastaler" <jason@dom.ain>'], [('', ''), ('Jason R. Mastaler', 'jason@dom.ain')]),
    (['User ((nested comment)) <foo@bar.com>'], [('User (nested comment)', 'foo@bar.com')]),  # nested comment
    (['Al Person <aperson@dom.ain>'], [('Al Person', 'aperson@dom.ain')]),  # the handling of a Header object
], ids=["comment", "empty-group", "garbage", "group-and-quoted", "nested-comment", "simple"])
def test_disguised_addresses_stdlib_cases(addresses, models):
    compared = [Address(name=v[0], address=v[1]) for v in models if v[0] or v[1]]
    parsed = Address.parse(addresses)
    assert [(a.name, a.address) for a in parsed] == [(a.name, a.address) for a in compared]


CONTACT = "Person2 <person2@example.com>"


def _eml_with_cc():
    return Envelope.load(path=EML).cc(CONTACT)


@pytest.mark.parametrize("value", [False, "", [False], [""]], ids=["false", "empty-str", "list-false", "list-empty"])
def test_removing_contact(value):
    """ Original contact should be removed """
    assert not _eml_with_cc().to(value).to()


def test_inserting_contact():
    assert _eml_with_cc().to(["", CONTACT]).to()[0] == CONTACT
    assert _eml_with_cc().to([CONTACT, False]).to()[0] == CONTACT
    assert len(_eml_with_cc().to([CONTACT, False]).to()) == 1


def test_removing_to_keeps_cc():
    assert _eml_with_cc().to("").cc() == [CONTACT]


@pytest.mark.cli
def test_removing_contact_cli(cli):
    header_row = "To: Person <person@example.com>"
    assert header_row in cli(stdin=EML)
    assert header_row not in cli("--to", "", stdin=EML)
    assert f"To: {CONTACT}" not in cli("--to", "", "contact", stdin=EML)


@pytest.mark.cli
def test_reading_contact(cli):
    assert "Person <person@example.com>" in cli("--to")
    assert "Harry Potter Junior via online--hey-list-open <some-list-email-address@example.com>" in cli("--from")


@pytest.mark.cli
@pytest.mark.parametrize(("flag", "expected"), [
    # if multiple recipients encountered, each displayed on its own line
    ("--to", "Person <person1@example.com>\nPerson2 <person2@example.com>"),
    ("--cc", "Person3 <person3@example.com>\nPerson4 <person4@example.com>"),
    ("--bcc", "Person5 <person5@example.com>"),
    ("--reply-to", "Person6 <person6@example.com>"),
])
def test_reading_contact_from_charset_eml(cli, flag, expected):
    assert expected in cli(flag, stdin=CHARSET)


def test_empty_contact():
    """ Be sure to receive an address even if the header misses. """
    e1 = Envelope("Empty message")
    assert isinstance(e1.from_(), Address)
    assert isinstance(e1.to(), list)
    assert isinstance(e1.cc(), list)
    assert isinstance(e1.bcc(), list)
    assert isinstance(e1.reply_to(), list)
    assert not e1.from_()
    assert e1.from_().address == ""


def test_loaded_contact_without_name():
    e2 = Envelope.load("From: test@example.com\n\nEmpty message")
    assert isinstance(e2.from_(), Address)
    assert e2.from_()
    assert e2.header("from")
    assert e2.header("From")
    assert not e2.header("sender")
    assert e2.from_().name == ""


def test_loaded_contact_with_name():
    e3 = Envelope.load("From: Person <test@example.com>\n\nEmpty message")
    assert e3.from_()
    assert e3.from_().name == "Person"
    assert e3.from_().is_valid()


def test_loaded_invalid_contact():
    e4 = Envelope.load("From: Invalid\n\nEmpty message")
    assert e4.from_()
    assert e4.from_().address == "Invalid"
    assert e4.from_().name == ""
    assert not e4.from_().is_valid()


@pytest.mark.parametrize(("value", "expected"), [
    (IDENTITY_1, [IDENTITY_1]),
    ((IDENTITY_1,), [IDENTITY_1]),
    ([IDENTITY_1, IDENTITY_2], [IDENTITY_1, IDENTITY_2]),
    ((IDENTITY_1, IDENTITY_2), [IDENTITY_1, IDENTITY_2]),
    # single string with multiple recipients
    (f"{IDENTITY_1}, {IDENTITY_2}", [IDENTITY_1, IDENTITY_2]),
    (f"{IDENTITY_1}; {IDENTITY_2}", [IDENTITY_1, IDENTITY_2]),
    ((f"{IDENTITY_1}; {IDENTITY_2}", IDENTITY_3), [IDENTITY_1, IDENTITY_2, IDENTITY_3]),
    ((x for x in (IDENTITY_1, IDENTITY_2)), [IDENTITY_1, IDENTITY_2]),
], ids=["str", "tuple-one", "list", "tuple", "comma", "semicolon", "mixed", "generator"])
def test_multiple_recipients_format(value, expected):
    """ You can use iterables like tuple, list, generator, set, frozenset for specifying multiple values """
    assert Envelope(MESSAGE).to(value).to() == expected


@pytest.mark.parametrize(("value", "extra", "expected"), [
    ({IDENTITY_1, IDENTITY_2}, None, {IDENTITY_1, IDENTITY_2}),
    ({IDENTITY_1, IDENTITY_2}, IDENTITY_1, {IDENTITY_1, IDENTITY_2}),
    ({IDENTITY_1, IDENTITY_2}, IDENTITY_3, {IDENTITY_1, IDENTITY_2, IDENTITY_3}),
    (frozenset([IDENTITY_1, IDENTITY_2]), None, {IDENTITY_1, IDENTITY_2}),
], ids=["set", "set-add-existing", "set-add-new", "frozenset"])
def test_multiple_recipients_unordered(value, extra, expected):
    e = Envelope(MESSAGE).to(value)
    if extra:
        e = e.to(extra)
    assert set(e.to()) == expected
