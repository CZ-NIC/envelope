import sys
from .envelope import Envelope

sys.modules[__name__] = Envelope  # to allow dynamic module call `import envelope; envelope(...)`
envelope = Envelope  # to support static inspection autocompletion `from envelope import envelope`
Envelope.envelope = Envelope  # point `from envelope import envelope` at working `import envelope` at runtime