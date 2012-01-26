
from abc import ABCMeta
from .Interfaces import MemReaderInterface, ReadError
from .Utile import *
from .RecursiveFind import *

class MemReaderBase( RecursiveFind ):
    """ Few basic functions for memory reader, still abstruct """
    __metaclass__ = ABCMeta

    def __init__(self):
        self.solveAddr      = None
        self.findInSymbols  = None
        self.findSymbol     = None        

        self.dd = self.readNPrintDwords
        self.db = self.readNPrintBin
        self.dw = self.readNPrintWords
        self.dq = self.readNPrintQwords

    def resolveOffsetsList( self, start, l, isVerbose=False, isLookingForCycles=True ):
        """
        A quick way jump from one pointer to another.
        Starting from start address, reading the pointer at (start + l[0]), and then reads the pointer at the last result + l[1] and so on.
        The verbose option would print all of the pointers including the starting address.
        The isLookingForCycles option would alert the user in case one pointer is read more than once during the offsets walk.
        """
        result = [start]
        readFail = False
        cycleFound = False
        try:
            for i in l:
                nextAddr = self.readAddr(result[-1]+i)
                if nextAddr in result:
                    cycleFound = True
                result.append(nextAddr)
        except WindowsError as e:
            readFail = True
            result.append(-1)
        except ReadError as e:
            readFail = True
            result.append(-1)
        if True == isVerbose:
            if None != self.solveAddr:
                outputString = '['
                for i in range(len(result)):
                    addr = result[i]
                    addrName = self.solveAddr(addr)
                    if None != addrName:
                        outputString += addrName
                    else:
                        outputString += hex(addr)
                    if i != (len(result) - 1):
                        outputString += ', '
                outputString += ']'
                print(outputString)
            else:
                print(', '.join([hex(x) for x in result]))
            if readFail:
                print("Could not resolve all offsets")
        if True == isLookingForCycles and True == cycleFound:
            print("Offsets path contains a cycle")
        return result

    def readNPrintQwords( self, addr, length=0x100, isNoBase=True, itemsInRow=4 ):
        """
        Display memory as QWords tabls, does not return anything
        """
        if isNoBase:
            printAsQwordsTable(self.readMemory(addr, length), itemsInRow=itemsInRow)
        else:
            printAsQwordsTable(self.readMemory(addr, length), addr, itemsInRow=itemsInRow)

    def readNPrintDwords( self, addr, length=0x100, isNoBase=True, itemsInRow=8 ):
        """
        Display memory as DWords tabls, does not return anything
        """
        if isNoBase:
            printAsDwordsTable(self.readMemory(addr, length), itemsInRow=itemsInRow)
        else:
            printAsDwordsTable(self.readMemory(addr, length), addr, itemsInRow=itemsInRow)

    def readNPrintWords( self, addr, length=0x100, isNoBase=True, itemsInRow=0x10 ):
        """
        Display memory as Words tabls, does not return anything
        """
        if isNoBase:
            printAsWordsTable(self.readMemory(addr, length), itemsInRow=itemsInRow)
        else:
            printAsWordsTable(self.readMemory(addr, length), addr, itemsInRow=itemsInRow)

    def readNPrintBin( self, addr, length=0x100, isNoBase=True, itemsInRow=0x10 ):
        """
        Display memory as bytes tabls, does not return anything
        """
        if isNoBase:
            print(DATA(self.readMemory(addr, length), itemsInRow=itemsInRow))
        else:
            print(DATA(self.readMemory(addr, length), addr, itemsInRow=itemsInRow))


