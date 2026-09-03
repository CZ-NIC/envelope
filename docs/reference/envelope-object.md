# Envelope object

## Converting object to str or bool

When successfully signing, encrypting or sending, object is resolvable to True and signed text / produced e-mail could be obtained via str().

```python3
o = Envelope("message", sign=True)
str(o)  # signed text
bool(o)  # True
```

## Object equality
Envelope object is equal to a `str`, `bytes` or another `Envelope` if their `bytes` are the same.
```python3
# Envelope objects are equal
sign = {"message": "message", "sign": True}
Envelope(**sign) == Envelope(**sign)  # True
bytes(Envelope(**sign))  # because their bytes are the same
# b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nmessage\n-----BEGIN PGP SIGNATURE-----\n\niQEzBAEBCgAdFiE...\n-----END PGP SIGNATURE-----\n'

# however, result of a PGP encrypting produces always a different output
encrypt = {"message": "message", "encrypt": True, "from_": False, "to": "person@example.com"}
Envelope(**encrypt) != Envelope(**encrypt)  # Envelope objects are not equal
```

