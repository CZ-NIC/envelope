# Sending
  * **send**: Send the message to the recipients by e-mail. True (blank in *CLI*) to send now or False to print out debug information.
    * **--send**
    * **.send(send=True, sign=None, encrypt=None)**
        * *send*: True to send now. False (or 0/false/no in *CLI*) to print debug information.
        * Returns the object back which converted to bool returns True if the message has been sent successfully.
    * **Envelope(send=)**

    ```bash
    $ envelope --to "user@example.org" --message "Hello world" --send 0
    ****************************************************************************************************
    Have not been sent from - to user@example.org

    Content-Type: text/html; charset="utf-8"
    Content-Transfer-Encoding: 7bit
    MIME-Version: 1.0
    Subject:
    From:
    To: user@example.org
    Date: Mon, 07 Oct 2019 16:13:37 +0200
    Message-ID: <157045761791.29779.5279828659897745855@...>

    Hello world
    ```
  * **subject**: Mail subject. Gets encrypted with GPG, stays visible with S/MIME.
    * **--subject**
    * **.subject(text=None, encrypt=None)**:
        * `text` Subject text.
        * `encrypt` Text used instead of the real protected subject while PGP encrypting. False to not encrypt.
        * If neither parameter specified, current subject returned.
    * **Envelope(subject=)**
    * **Envelope(subject_encrypted=)**
  * **date**:
    * **.date(date)** `str|False` Specify Date header (otherwise Date is added automatically). If False, the Date header will not be added automatically.
  * **smtp**: SMTP server
    * **--smtp**
    * **.smtp(host="localhost", port=25, user=, password=, security=, timeout=3, attempts=3, delay=3, local_hostname=None)**
    * **Envelope(smtp=)**
    * Parameters:
        * `host` May include hostname or any of the following input formats (ex: path to an INI file or a `dict`)
        * `security` If not set, automatically set to `starttls` for port *587* and to `tls` for port *465*
        * `timeout` How many seconds should SMTP wait before timing out.
        * `attempts` How many times we try to send the message to an SMTP server.
        * `delay` How many seconds to sleep before re-trying a timed out connection.
        * `local_hostname` FQDN of the local host in the HELO/EHLO command.
    * Input format may be in the following form:
        * `None` default localhost server used
        * standard [`smtplib.SMTP`](https://docs.python.org/3/library/smtplib.html) object
        * `list` or `tuple` having `host, [port, [username, password, [security, [timeout, [attempts, [delay, [local_hostname]]]]]]]` parameters
            * ex: `envelope --smtp localhost 125 me@example.com` will set up host, port and username parameters
        * `dict` specifying {"host": ..., "port": ...}
            * ex: `envelope --smtp '{"host": "localhost"}'` will set up host parameter
        * `str` hostname or path to an INI file (existing file, ending at `.ini`, with the section [SMTP])
            ```ini
            [SMTP]
            host = example.com
            port = 587
            ```
    * Do not fear to pass the `smtp` in a loop, we make just a single connection to the server. If timed out, we attempt to reconnect once.
    ```python3
    smtp = "localhost", 25
    for mail in mails:
        Envelope(...).smtp(smtp).send()
    ```
  * **attachments**
    * **--attach**: Path to the attachment, followed by optional file name to be used and/or mime type. This parameter may be used multiple times.
    ```bash
    envelope --attach "/tmp/file.txt" "displayed-name.txt" "text/plain" --attach "/tmp/another-file.txt"
    ```
    * **.attach(attachment=, mimetype=, name=, path=, inline=)**:
        ```python3
        Envelope().attach(path="/tmp/file.txt").attach(path="/tmp/another-file.txt")
        ```
        * Three different usages when specifying contents:
            * **.attach(attachment=, mimetype=, name=)**: You can put [any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents) of a single attachment into *attachment* and optionally add mime type or displayed file name.
            * **.attach(mimetype=, name=, path=)**: You can specify path and optionally mime type or displayed file name.
            * **.attach(attachment=)**: You can put a list of attachments. The list may contain tuples: `contents [,mime type] [,file name] [, True for inline]`.
        * **.attach(inline=True|str)**: Specify content-id (CID) to reference the image from within HTML message body.
           * True: Filename or attachment or path file name is set as CID.
           * str: The attachment will get this CID.
           ```python3
           from pathlib import Path
           Envelope().attach(Path("file.jpg"), inline=True) # <img src='cid:file.jpg' />
           Envelope().attach(b"GIF89a\x03\x00\x03...", name="file.gif", inline=True) # <img src='cid:file.gif' />
           Envelope().attach(Path("file.jpg"), inline="foo") # <img src='cid:foo' />

           # Reference it like: .message("Hey, this is an inline image: <img src='cid:foo' />")
          ```
    * **Envelope(attachments=)**: Attachment or their list. Attachment is defined by [any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents), optionally in tuple with the file name to be used in the e-mail and/or mime type and/or True for being inline: `contents [,mime type] [,file name] [, True for inline]`
    ```python3
    Envelope(attachments=[(Path("/tmp/file.txt"), "displayed-name.txt", "text/plain"), Path("/tmp/another-file.txt")])
    ```
    * **mime**: Sets contents mime subtype: "**auto**" (default), "**html**" or "**plain**" for plain text.
        Maintype is always set to "text".
        If a line is longer than 1000 characters, makes the message be transferred safely by bytes (otherwise these non-standard long lines might cause a transferring SMTP server to include line breaks and redundant spaces that might break up ex: DKIM signature).
        In case of `Content-Type` header put to the message, **mime** section functionality **is skipped**.
        * **--mime SUBTYPE**
        * **.mime(subtype="auto", nl2br="auto")**
            * nl2br: True will append `<br>` to every line break in the HTML message. "auto": line breaks are changed only if there is no `<br` or `<p` in the HTML message,
        * **Envelope(mime=)**
    * **headers**: Any custom headers (these will not be encrypted with GPG nor S/MIME)
        * **--header name value** (may be used multiple times)
        * **.header(name, value=None, replace=False)**
            * `value` If None, returns value of the header or its list if the header was used multiple times. (Note that To, Cc, Bcc and Reply-To headers always return list.)
            * `replace` If True, any header of the `key` name are removed first and if `val` is None, the header is deleted. Otherwise another header of the same name is appended.
            ```python3
            Envelope().header("X-Mailer", "my-app").header("X-Mailer") # "my-app"
            Envelope().header("Generic-Header", "1") \
                      .header("Generic-Header", "2") \
                      .header("Generic-Header") # ["1", "2"]
            ```
        * **Envelope(headers=[(name, value)])**

        Equivalent headers:
        ```bash
        envelope --header X-Mailer my-app
        ```

        ```python3
        Envelope(headers=[("X-Mailer", "my-app")])
        Envelope().header("X-Mailer", "my-app")
        ```
## Specific headers
These helpers are available via fluent interface.

* **.list_unsubscribe(uri=None, one_click=False, web=None, email=None)**: You can specify either url, email or both.
    * **.list_unsubscribe(uri)**: We try to determine whether this is e-mail and prepend brackets and 'https:'/'mailto:' if needed. Ex: `me@example.com?subject=unsubscribe`, `example.com/unsubscribe`, `<https://example.com/unsubscribe>`
    * **.list_unsubscribe(email=)**: E-mail address. Ex: `me@example.com`, `mailto:me@example.com`
    * **.list_unsubscribe(web=, one_click=False)**: Specify URL. Ex: `example.com/unsubscribe`, `http://example.com/unsubscribe`. If `one_click=True`, rfc8058 List-Unsubscribe-Post header is added. This says user can unsubscribe with a single click that is realized by a POST request in order to prevent e-mail scanner to access the unsubscribe page by mistake. A 'https' url must be present.

    ```python3
    # These will produce:
    # List-Unsubscribe: <https://example.com/unsubscribe>
    Envelope().list_unsubscribe("example.com/unsubscribe")
    Envelope().list_unsubscribe(web="example.com/unsubscribe")
    Envelope().list_unsubscribe("<https://example.com/unsubscribe>")

    # This will produce:
    # List-Unsubscribe: <https://example.com/unsubscribe>, <mailto:me@example.com?subject=unsubscribe>
    Envelope().list_unsubscribe("example.com/unsubscribe", mail="me@example.com?subject=unsubscribe")
    ```

* **.auto_submitted**:
    * **.auto_submitted(val="auto-replied")**: Direct response to another message by an automatic process.
    * **.auto_submitted.auto_generated()**: automatic (often periodic) processes (such as UNIX "cron jobs") which are not direct responses to other messages
    * **.auto_submitted.no()**: message was originated by a human

```python3
Envelope().auto_submitted()  # mark message as automatic
Envelope().auto_submitted.no()  # mark message as human produced
```
