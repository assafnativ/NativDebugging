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
else:
    import Linux
    __all__.append('Linux')
