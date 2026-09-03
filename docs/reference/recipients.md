# Recipients
* **from**: E-mail – needed to choose our key if encrypting.
    * **--from** E-mail. Empty to read value.
    * **--no-from** Declare we want to encrypt and never decrypt back.
    * **.from_(email)**: E-mail | False | None. If None, current `From` returned as an [Address](https://cz-nic.github.io/envelope/reference/supportive/#address) object (even an empty one).
    * **Envelope(from_=)**: Sender e-mail or False to explicitly omit. When encrypting without sender, we do not use their key so that we will not be able to decipher again.
    ```python3
    # These statements are identical.
    Envelope(from_="identity@example.com")
    Envelope().from_("identity@example.com")

    # This statement produces both From header and Sender header.
    Envelope(from_="identity@example.com", headers=[("Sender", "identity2@example.com")])

    # reading an Address object
    a = Envelope(from_="identity@example.com").from_()
    a == "identity@example.com", a.host == "example.com"
    ```
* **to**: E-mail or more in an iterable. When encrypting, we use keys of these identities. Multiple addresses may be given in a string, delimited by a comma (or semicolon). (The same is valid for `to`, `cc`, `bcc` and `reply-to`.)
    * **--to**: One or more e-mail addresses. Empty to read.
      ```bash
      $ envelope --to first@example.com second@example.com --message "hello"
      $ envelope --to
      first@example.com
      second@example.com
      ```
    * **.to(email_or_more)**: If None, current list of [Addresses](https://cz-nic.github.io/envelope/reference/supportive/#address) returned. If False or "", current list is cleared.
    ```python3
        Envelope()
            .to("person1@example.com")
            .to("person1@example.com, John <person2@example.com>")
            .to(["person3@example.com"])
            .to()  # ["person1@example.com", "John <person2@example.com>", "person3@example.com"]
    ```
    * **Envelope(to=)**: E-mail or more in an iterable.
* **cc**: E-mail or more in an iterable. Multiple addresses may be given in a string, delimited by a comma (or semicolon). (The same is valid for `to`, `cc`, `bcc` and `reply-to`.)
    * **--cc**: One or more e-mail addresses. Empty to read.
    * **.cc(email_or_more)**: If None, current list of [Addresses](https://cz-nic.github.io/envelope/reference/supportive/#address) returned. If False or "", current list is cleared.
        ```python3
        Envelope()
            .cc("person1@example.com")
            .cc("person1@example.com, John <person2@example.com>")
            .cc(["person3@example.com"])
            .cc()  # ["person1@example.com", "John <person2@example.com>", "person3@example.com"]
        ```
    * **Envelope(cc=)**
* **bcc**: E-mail or more in an iterable. Multiple addresses may be given in a string, delimited by a comma (or semicolon). (The same is valid for `to`, `cc`, `bcc` and `reply-to`.) The header is not sent.
    * **--bcc**: One or more e-mail addresses. Empty to read.
    * **.bcc(email_or_more)**: If None, current list of [Addresses](https://cz-nic.github.io/envelope/reference/supportive/#address) returned. If False or "", current list is cleared.
    * **Envelope(bcc=)**
* **reply-to**: E-mail or more in an iterable. Multiple addresses may be given in a string, delimited by a comma (or semicolon). (The same is valid for `to`, `cc`, `bcc` and `reply-to`.) The field is not encrypted.
    * **--reply-to**: E-mail address or empty to read value.
    * **.reply_to(email_or_more)**: If None, current list of [Addresses](https://cz-nic.github.io/envelope/reference/supportive/#address) returned. If False or "", current list is cleared.
    * **Envelope(reply_to=)**
* **from_addr**: SMTP envelope MAIL FROM address.
    * **--from-addr**: E-mail address or empty to read value.
    * **.from_addr(email)**: E-mail or False. If None, current `SMTP envelope MAIL FROM` returned as an [Address](https://cz-nic.github.io/envelope/reference/supportive/#address) object (even an empty one).
    * **.Envelope(from_addr=)**
