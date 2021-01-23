from .envelope import Envelope
from .utils import Address

Envelope.default = Envelope()  # unfortunately, this line executes when launched as module from bash, we loose ~ 5 ms
__all__ = ["Envelope", "Address"]
