#import sys

from .envelope import Envelope

from datetime import datetime, timedelta

__all__ = ["Envelope"]

#sys.modules[__name__] = envelope  # to allow dynamic module call `import envelope; envelope(...)`
#envelope = envelope  # to support static inspection autocompletion `from envelope import envelope`
#envelope.envelope = envelope  # point `from envelope import envelope` at working `import envelope` at runtime
#envelope.Envelope = envelope
