# Usage
Envelope offers the very same functionality through three interfaces, so pick whichever fits the moment:

* **CLI** – for shell scripts and one-off terminal use.
* **Fluent interface** – for application code, when your IDE's autocompletion should guide you method by method.
* **One-liner function** – for application code, when you already know every parameter you want to set and prefer a single call.

As an example, let's produce in three equal ways an `output_file` with the GPG-encrypted "Hello world" content.
## CLI
Launch as a CLI application in terminal, see `envelope --help`

```bash
envelope --message "Hello world" \
               --output "/tmp/output_file" \
               --from "me@example.com" \
               --to "remote_person@example.com" \
               --encrypt-path "/tmp/remote_key.asc"
```
## Module: fluent interface
Comfortable way to create the structure if your IDE supports autocompletion.
```python3
from envelope import Envelope
Envelope().message("Hello world")\
    .output("/tmp/output_file")\
    .from_("me@example.com")\
    .to("remote_person@example.com")\
    .encrypt(key_path="/tmp/remote_key.asc")
```

## Module: one-liner function
You can easily write a one-liner function that encrypts your code or sends an e-mail from within your application when imported as a module. See `pydoc3 envelope` or documentation below.

```python3
from envelope import Envelope
Envelope(message="Hello world",
        output="/tmp/output_file",
        from_="me@example.com",
        to="remote_person@example.com",
        encrypt="/tmp/remote_key.asc")
```
