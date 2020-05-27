#import sys

from .envelope import Envelope

__all__ = ["Envelope"]


# XXXX delete when new version of Convey is ready
envelope = Envelope
__all__ = ["Envelope", "envelope"]

#sys.modules[__name__] = envelope  # to allow dynamic module call `import envelope; envelope(...)`
#envelope = envelope  # to support static inspection autocompletion `from envelope import envelope`
#envelope.envelope = envelope  # point `from envelope import envelope` at working `import envelope` at runtime
#envelope.Envelope = envelope
