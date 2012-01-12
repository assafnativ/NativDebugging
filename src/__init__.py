__all__ = [
        "Patterns",
        "Interfaces",
        "DebuggerBase",
        "MemReaderBase",
        "QtWidgets",
        "GUIDisplayBase",
        "Utile" ]

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
