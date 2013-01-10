__all__ = [
        "Interfaces",
        "DebuggerBase",
        "MemReaderBase",
        "QtWidgets",
        "GUIDisplayBase",
        "Utile" ]
from . import File
from . import Patterns
__all__.append('File')
__all__.append('Patterns')

import sys
if sys.platform.lower().startswith('win'):
    from . import Win32
    __all__.append('Win32')
elif sys.platform.lower().startswith('linux'):
    from . import Linux
    __all__.append('Linux')
else:
    from . import Unix
    __all__.append('Unix')
