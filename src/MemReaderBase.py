
from abc import ABCMeta
from .Interfaces import MemReaderInterface
from .Utile import *
from .RecursiveFind import *

class MemReaderBase( RecursiveFind ):
    """ Few basic functions for memory reader, still abstruct """
    __metaclass__ = ABCMeta

    def __init__(self):
        self.solveAddr      = None
        self.findInSymbols  = None
        self.findSymbol     = None        

    def resolveOffsetsList( self, start, l, isVerbos=False ):
        result = [start]
        for i in l:
            result.append(self.readAddr(result[-1]+i))
        if True == isVerbos:
            if None != self.solveAddr:
                outputString = '['
                for i in xrange(len(result)):
                    addr = result[i]
                    addrName = self.solveAddr(addr)
                    if None != addrName:
                        outputString += addrName
                    else:
                        outputString += hex(addr)
                    if i != (len(result) - 1):
                        outputString += ', '
                outputString += ']'
                print outputString
            else:
                print map(hex, result)
        return result

    def readNPrintQwords( self, addr, length=0x100, isNoBase=True, itemsInRow=4 ):
        if isNoBase:
            printAsQwordsTable(self.readMemory(addr, length), itemsInRow=itemsInRow)
        else:
            printAsQwordsTable(self.readMemory(addr, length), addr, itemsInRow=itemsInRow)

    def readNPrintDwords( self, addr, length=0x100, isNoBase=True, itemsInRow=8 ):
        if isNoBase:
            printAsDwordsTable(self.readMemory(addr, length), itemsInRow=itemsInRow)
        else:
            printAsDwordsTable(self.readMemory(addr, length), addr, itemsInRow=itemsInRow)

    def readNPrintWords( self, addr, length=0x100, isNoBase=True, itemsInRow=0x10 ):
        if isNoBase:
            printAsWordsTable(self.readMemory(addr, length), itemsInRow=itemsInRow)
        else:
            printAsWordsTable(self.readMemory(addr, length), addr, itemsInRow=itemsInRow)

    def readNPrintBin( self, addr, length=0x100, isNoBase=True, itemsInRow=0x10 ):
        if isNoBase:
            print DATA(self.readMemory(addr, length), itemsInRow=itemsInRow)
        else:
            print DATA(self.readMemory(addr, length), addr, itemsInRow=itemsInRow)


