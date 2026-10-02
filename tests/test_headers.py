import sys

import pytest

from envelope import Envelope
from helpers import MESSAGE


def test_generic_header_manipulation():
    # Add a custom header and delete it
    e = Envelope(MESSAGE).subject("my subject").header("custom", "1")
    assert e.header("custom") == "1"
    assert e.header("custom", replace=True) is e

    # Add a header multiple times
    e.header("custom", "2").header("custom", "3")
    # Receive list
    assert e.header("custom") == ["2", "3"]
    # Replace by single value
    assert e.header("custom", "4", replace=True) is e
    # Receive string
    assert e.header("custom") == "4"
    # Delete the header and read None
    assert e.header("custom", None, replace=True) is e
    assert e.header("custom") is None


def test_specific_header_manipulation():
    """ Specific headers are stored in instance attributes.
        Ex: It is useful to have Subject as a special header since it can be encrypted.
        Ex: It is useful to have Cc as a special header since it can hold the list of receivers.
    """
    s = "my subject"
    id1, id2, id3 = "person@example.com", "person2@example.com", "person3@example.com"
    e = Envelope(MESSAGE).subject(s).header("custom", "1").cc(id1)  # set headers via their specific methods
    assert e.header("subject") == s  # access via .header
    assert e.subject() == s  # access via specific method .subject
    assert e.header("subject", replace=True) is e
    assert e.header("subject") == ""  # the original asserted identity with "" (interned empty str)
    assert e.header("subject", s).subject() == s  # set via generic method

    assert e.header("cc", id2).header("cc") == [id1, id2]  # access via .header
    assert e.cc() == [id1, id2]
    assert e.header("cc", replace=True) is e
    assert e.cc() == []
    assert e.header("cc", id3) is e
    # cc and bcc headers always return list as documented (which is maybe not ideal)
    assert e.header("cc") == [id3]


def test_date_header_can_be_disabled():
    """ Automatic adding of the Date header can be disabled. """
    assert "Date: " in str(Envelope(MESSAGE))
    assert "Date: " not in str(Envelope(MESSAGE).date(False))


def test_email_addresses():
    e = (Envelope()
         .cc("person1@example.com")
         .to("person2@example.com")  # add as string
         .to(["person3@example.com", "person4@example.com"])  # add as list
         .to("person5@example.com")
         .to("Duplicated <person5@example.com>")  # duplicated person should be ignored without any warning
         # we can delimit both by comma (standard) and semicolon (invalid but usual)
         .to(["person4@example.com; Sixth <person6@example.com>, Seventh <person7@example.com>"])
         # even invalid delimiting works
         .to(["person8@example.com,  , ; Ninth <person9@example.com>, Seventh <person7@example.com>"])
         .to("Named person 1 again <person1@example.com>")  # appeared twice -> will be discarded
         .bcc("person10@example.com"))

    assert len(e.to()) == 9
    assert len(e.cc()) == 1
    assert len(e.recipients()) == 10
    assert type(",".join(e.to())) is str  # we can join elements as strings
    assert "Sixth <person6@example.com>" in e.to()  # we can look up a specific recipient


@pytest.mark.skipif(sys.version_info < (3, 11), reason="address parsing is lenient before Python 3.11")
def test_invalid_email_addresses():
    """ If we discard silently every invalid e-mail address received,
    the user would not know their recipients are not valid. """
    e = Envelope().to('person1@example.com, [invalid!email], person2@example.com')
    assert len(e.to()) == 3
    assert not e.check(check_mx=False, check_smtp=False)

    e = Envelope().to('person1@example.com, person2@example.com')
    assert e.check(check_mx=False, check_smtp=False)
