
from .Interfaces import GUIDisplayInterface
try:
    from .QtWidgets import *
    IS_QT_SUPPORTED = True
except ImportError as e:
    IS_QT_SUPPORTED = False

class GUIDisplayBase( GUIDisplayInterface ):
    """ A basic n' simple implementation of GUI display using QT """
    
    def _hexDisplay(self, address, length=0x1000, showOffsets=False, size=4):
        updateCallback = lambda :self.readMemory(address, length)
        if showOffsets:
            newWindow = HexView(self.readMemory(address, length), start_address=0, item_size=size, updateCallback=updateCallback)
        else:
            newWindow = HexView(self.readMemory(address, length), start_address=address, item_size=size, updateCallback=updateCallback)
        newWindow.show()
        return newWindow

    def _mapDisplay(self, address, length=0x1000, colorMap=None):
        """
        Display memory in a bytes map form
        Arguments:
            color_map - a list converting from byte value to color (item index = byte value)
        Note:
            You can use setPixelDimensions, setStartOffset and setItemsPerRow to set the details
            after the creation of the Window.
            Use saveImage to save a bitmap image of the memory dump.
            Use updateData to reread the memory.
        """
        updateCallback = lambda :self.readMemory(address, length)
        newWindow = MemoryMap(self.readMemory(address, length), color_map=colorMap, updateCallback=updateCallback)
        newWindow.show()
        return newWindow

    def _unsupported(self, *args, **kw):
        raise NotImplementedError("Unsupported function")

    def mapDisplay(self, *args, **kw):
        """
        Display memory in a bytes map form
        Arguments:
            color_map - a list converting from byte value to color (item index = byte value)
        Note:
            You can use setPixelDimensions, setStartOffset and setItemsPerRow to set the details
            after the creation of the Window.
            Use saveImage to save a bitmap image of the memory dump.
            Use updateData to reread the memory.
        """
        if IS_QT_SUPPORTED:
            self.mapDisplay = self._mapDisplay
        else:
            self.mapDisplay = self._unsupported
        return self.mapDisplay(*args, **kw)

    def hexDisplay(self, *args, **kw):
        if IS_QT_SUPPORTED:
            self.hexDisplay = self._hexDisplay
        else:
            self.hexDisplay = self._unsupported
        return self.hexDisplay(*args, **kw)

