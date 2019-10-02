import sys
from .envelope import Envelope

sys.modules[__name__] = Envelope  # to allow dynamic module call `import envelope; envelope(...)`
Envelope.envelope = Envelope  # to support static inspection autocompletion
