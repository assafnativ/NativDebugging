__all__ = [
        "Patterns",
        "Interfaces",
        "MemReaderBase",
        "QtWidgets",
        "GUIDisplayBase",
        "Utile" ]

import sys
if sys.platform.lower().startswith('win'):
    import Win32
    __all__.append('Win32')
elif sys.platform.lower().startswith('linux'):
    import Linux
    __all__.append('Linux')
else:
    import Unix
    __all__.append('Unix')
