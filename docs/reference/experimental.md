# Experimental

Since we tend to keep the API simple and do the least amount of backward incompatible changes, it is hard to decide the right way. Your suggestions are welcome! Following methods have no stable API, hence their name begins with an underscore.

* `_report()`: Accessing `multipart/report`.

Currently only [XARF](http://xarf.org/) is supported in the moment. You may directly access the fields, without any additional `json` parsing.

```python3
if xarf := Envelope.load(path="xarf.eml")._report():
  print(xarf['SourceIp'])  # '192.0.2.1'
```

* `_check_auth()`: To determine whether DMACR, SPF and DKIM are alright in a loaded message.
```python3
from envelope import Envelope
auth = Envelope.load(path="test.eml")._check_auth()
auth # <AuthResult spf='pass', dkim='pass', dmarc='pass', spf_received='pass', verdict='pass', failure_reason=None>
if auth:  # Use the output object as bool. It is True only if all present checks are 'pass'.
  ...
```


