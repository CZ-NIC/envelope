# Reference

Both `envelope --help` for CLI arguments help and `pydoc3 envelope` to see module arguments help should contain same information as here.

## Command list
All parameters are optional.

* **--param** is used in CLI
* **.param(value)** denotes a positional argument
* **.param(value=)** denotes a keyword argument
* **Envelope(param=)** is a one-liner argument

## Any attainable contents
Whenever any attainable contents is mentioned, we mean plain **text**, **bytes** or **stream** (ex: from `open()`). In *module interface*, you may use a **`Path`** object to the file. In *CLI interface*, additional flags are provided instead.

If the object is not accesible, it will immediately raise `FileNotFoundError`.
```python3
Envelope().attach(path="file.jpg")
# Could not fetch file .../file.jpg
# FileNotFoundError: [Errno 2] No such file or directory: 'file.jpg'
```
