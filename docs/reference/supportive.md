# Supportive
  * **.recipients()**: Return set of all recipients – `To`, `Cc`, `Bcc`
    * **.recipients(clear=True)**: All `To`, `Cc` and `Bcc` recipients are removed and the `Envelope` object is returned.
  * **attachments**: Access the list of attachments.
      * **--attachments [NAME]** Get the list of attachments or a contents of the one specified by `NAME`
      * **.attachments(name=None, inline=None)**
        * **name** (str): The name of the only desired attachment to be returned.
        * **inline** (bool): Filter inline/enclosed attachments only.
        * *Attachment* object has the attributes *.name* file name, *.mimetype*, *.data* raw data
            * if casted to *str*/*bytes*, its raw *.data* are returned
  * **.copy()**: Return deep copy of the instance to be used independently.
    ```python3
    factory = Envelope().cc("original@example.com").copy
    e1 = factory().to("to-1@example.com")
    e2 = factory().to("to-2@example.com").cc("additional@example.com")  #

    print(e1.recipients())  # {'to-1@example.com', 'original@example.com'}
    print(e2.recipients())  # {'to-2@example.com', 'original@example.com', 'additional@example.com'}
    ```
  * Read message and subject by **.message()** and **.subject()**
  * **preview**: Returns the string of the message or data as a human-readable text.
            Ex: whilst we have to use quoted-printable (as seen in __str__), here the output will be plain text.
    * **--preview**
    * **.preview()**
  * **check**: Check all e-mail addresses and SMTP connection and return True/False if succeeded. Tries to find SPF, DKIM and DMARC DNS records depending on the From's domain and print them out.
    * **--check**
    * **.check(check_mx=True, check_smtp=True)**
        * `check_mx` E-mail addresses can be checked for MX record, not only for their format.
        * `check_smtp` We try to connect to the SMTP host.

    ```bash
    $ envelope --smtp localhost 25 --from me@example.com --check
    SPF found on the domain example.com: v=spf1 -all
    See: dig -t SPF example.com && dig -t TXT example.com
    DKIM found: ['v=DKIM1; g=*; k=rsa; p=...']
    Could not spot DMARC.
    Trying to connect to the SMTP...
    Check succeeded.
    ```
  * **.as_message()**: Generates an email.message.Message object.
     ```python3
     e = Envelope("hello").as_message()
     print(type(e), e.get_payload())  # <class 'email.message.EmailMessage'> hello\n
     ```
     Note: due to a bug in a standard Python library https://github.com/python/cpython/issues/99533 and #19 you void GPG when you access the message this way wihle signing an attachment with a name longer than 34 chars.
  * **load**: Parse [any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents) (including email.message.Message) like an EML file to build an Envelope object. It can decrypt the message and parse its (inline or enclosed) attachments.

    Note that if you send this reconstructed message, you might not receive it due to Message-ID duplication — delete at least the `Message-ID` header prior to re-sending.

    (*static*) **.load(message, \*, path=None, key=None, cert=None, gnupg_home=None)**

    * **message**: [Any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents)
    * **path**: Path to the file, alternative to the `message`
    * **key**, **cert**: Specify when decrypting an S/MIME message (may be bundled together to the `key`)
    * **gnupg_home**: Path to the GNUPG_HOME or None if the environment default should be used.

    ```python3
    Envelope.load("Subject: testing message").subject()  # "testing message"
    ```

    In bash, blank `--subject` or `--message` flags display the respective value of the loaded message. Use **--load FILE** to load an EML file:

    ```bash
    $ envelope --load email.eml
    Content-Type: text/plain; charset="utf-8"
    Content-Transfer-Encoding: 7bit
    MIME-Version: 1.0
    Subject: testing message

    Message body

    $ envelope --load email.eml --subject
    testing message
    ```

    Content may also be piped in, with `envelope` run without any arguments:

    ```bash
    $ echo "Subject: testing message" | envelope
    Content-Type: text/plain; charset="utf-8"
    Content-Transfer-Encoding: 7bit
    MIME-Version: 1.0
    Subject: testing message

    $ cat email.eml | envelope

    $ envelope < email.eml
    ```
  * **smtp_quit()**: As Envelope tends to re-use all the SMTP instances, you may want to quit them explicitly. Either call this method to the Envelope class to close all the cached connections or to an Envelope object to close only the connection it currently uses.
    ```python3
    e = Envelope().smtp(server1).smtp(server2)
    e.smtp_quit()  # called on an instance → closes connection to `server2` only
    Envelope.smtp_quit()  # called on the class → closes both connections
    ```

## Address

Any e-mail address encountered is internally converted to an `Address(str)` object that can be imported from the `envelope` package. You can safely access following `str` properties:
* `.name` – the real name
* `.address` – the e-mail address
* `.host` – its domain
* `.user` – the user name part of the e-mail
```python3
from envelope import Address
a = Address("John <person@example.com>")
a.name == "John", a.address == "person@example.com", a.host == "example.com", a.user == "person"
```

Empty object works too. For example, if the `From` header is not set, we get an empty Address object. Still it is safe to access its properties.
```python3
a = Envelope.load("Empty message").from_()
bool(a) is False, a.host == ""
Address() == Address("") == "", Address().address == ""
```

Method `.casefold()` returns casefolded `Address` object which is useful for comparing with strings whereas comparing with other `Address` object casefolds automatically
```python3
a = Address("John <person@example.com>")
c = a.casefold()
a is not c, a == c, a.name == "john", a.name != c.name
```

Method `.is_valid(check_mx=False)` returns boolean if the format is valid. When `check_mx` set to `True`, MX server is inquired too.

Since the `Address` is a subclass of `str`, you can safely join such objects.

```python3
", ".join([a, a]) # "John <person@example.com>, "John <person@example.com>"
a + " hello"  #  "John <person@example.com> hello"
```

Address objects are equal if their e-mail address are equal. (Their real names might differ.)
Address object is equal to a string if the string contains its e-mail address or the whole representation.

```python3
"person@example.com" == Address("John <person@example.com>") == "John <person@example.com>"  # True
```

Concerning `to`, `cc`, `bcc` and `reply-to`, multiple addresses may always be given in a string, delimited by comma (or semicolon). The `.get(address:bool, name:bool)` method may be called on an `Address` object to filter the desired information.
```python3
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
```

For some exotic cases, Address tends to do the parsing job better than the underlying standard library (see the [bug report](https://github.com/python/cpython/issues/40889) from 2004).

```python3
from email.utils import parseaddr
from envelope import Address
parseaddr("alice@example.com <bob@example.malware>")
# ('', 'alice@example.com') -> empty name and wrong address
Address("alice@example.com <bob@example.malware>").address
# 'bob@example.malware' -> the right address
```

