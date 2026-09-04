# Reference

Both `envelope --help` for CLI arguments help and `pydoc3 envelope` to see module arguments help should contain same information as here.

## Command list
All parameters are optional.

* **--param** is used in CLI
* **.param(value)** denotes a positional argument
* **.param(value=)** denotes a keyword argument
* **Envelope(param=)** is a one-liner argument

## Any attainable contents
Whenever any attainable contents is mentioned, we mean plain **text**, **bytes** or a **stream** (ex: from `open()`). In *module interface*, you may also pass a **`Path`** object pointing to the file. In *CLI interface*, a dedicated flag is provided instead (ex: `--input` next to `--message`).

All of the following set the very same message:

```python3
from pathlib import Path
Envelope(message="Hello world")               # plain text
Envelope(message=b"Hello world")               # bytes
Envelope(message=Path("hello.txt"))            # path to a file containing "Hello world"
Envelope(message=open("hello.txt"))            # an open stream over the same file
```

If the object is not accessible, it will immediately raise `FileNotFoundError`.
```python3
Envelope().attach(path="file.jpg")
# Could not fetch file .../file.jpg
# FileNotFoundError: [Errno 2] No such file or directory: 'file.jpg'
```
