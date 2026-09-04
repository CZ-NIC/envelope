# Input / Output

## message
Message / body text. If no string is set, message gets read. Besides, when "Content-Transfer-Encoding" is set to "base64" or "quoted-printable", it gets decoded (useful when quickly reading an EML file content `cat file.eml | envelope --message`).

* **--message**: String. Empty to read.
* **--input**: *(CLI only)* Path to the message file. (Alternative to the `--message` parameter.)
* **.message()**: Read current message in `str`.
* **.message(text)**: Set the message to [any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents).
* **.message(path=None, alternative="auto", boundary=None)**
    * `path`: Path to the file.
    * `alternative`: "auto", "html", "plain" You may specify e-mail text alternative. Some e-mail readers prefer to display plain text version over HTML. By default, we try to determine content type automatically (see *mime*).
    * *boundary*: When specifying alternative, you may set e-mail boundary if you do not wish a random one to be created.
* **.body(path=None)**: Alias of `.message` (without `alternative` and `boundary` parameter)
* **.text(path=None)**: Alias of `.message` (without `alternative` and `boundary` parameter)
* **Envelope(message=)**: [Any attainable contents](https://cz-nic.github.io/envelope/reference/overview/#any-attainable-contents)

Setting `alternative`:

```python3
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
```

Equivalents for setting a string (in *Python* and in *Bash*).

```python3
Envelope(message="hello") == Envelope().message("hello")
```
```bash
envelope --message "hello"
```

Equivalents for setting contents of a file (in *Python* and in *Bash*).

```python3
from pathlib import Path
Envelope(message=Path("file.txt")) == Envelope(message=open("file.txt")) == Envelope.message(path="file.txt")
```
```bash
envelope --input file.txt
```

Envelope is sometimes able to handle wrong encoding or tries to print out a meaningful warning.

```python3
# Issue a warning when trying to represent a mal-encoded message.
b ="€".encode("cp1250")  # converted to bytes b'\x80'
e = Envelope(b)
repr(e)
# WARNING: Cannot decode the message correctly, plain alternative bytes are not in Unicode.
# Envelope(message="b'\x80'")

# When trying to output a mal-encoded message, we end up with a ValueError exception.
e.message()
# ValueError: Cannot decode the message correctly, it is not in Unicode. b'\x80'

# Setting up an encoding (even ex-post) solves the issue.
e.header("Content-Type", "text/plain;charset=cp1250")
e.message()  # '€'
```

## output
Path to file to be written to (else the contents is returned).

* **--output**
* **.output(output_file)**
* **Envelope(output=)**
