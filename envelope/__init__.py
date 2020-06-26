from .envelope import Envelope

Envelope.default = Envelope()  # unfortunately, this line executes when launched as module from bash, we loose ~ 5 ms
__all__ = ["Envelope"]
