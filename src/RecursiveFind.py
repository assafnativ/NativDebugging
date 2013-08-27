
from abc import ABCMeta
from .Interfaces import MemReaderInterface, ReadError
from .Utile import makeQwordsList, makeDwordsList

class RecursiveFind( MemReaderInterface ):
    """ Search for offsets using a recurisve method """
    __metaclass__ = ABCMeta

    def printRecursiveFindResult( self, result ):
        '''
        Description : prints a result returned from a binary search in a human friendly way
        Args:
                        result - list/tuple which holds the result to be displayed (starting address, offsets to data, name ??)
        Return Value : None, just prints the string
        '''
        print(('{0:s}\t{1:s}\t"{2:s}"'.format(hex(result[0]), ''.join(['{0:s}, '.format(hex(x)) for x in result[1]]), str(result[2]))))

    def _recursiveFind(self, targetValidator, startAddress, searchLength, pointerSize, targetReader, hops, alignment, limiter, path):
        if startAddress % alignment != 0:
            raise Exception("Not aligned")
        if isinstance(searchLength, list):
            nextSearchLength = searchLength[1:]
            currentSearchLenght = searchLength[0]
        else:
            nextSearchLength = searchLength
            currentSearchLenght = searchLength
        try:
            for offset in xrange(currentSearchLenght):
                addr = startAddress + offset
                if 0 == (addr % alignment):
                    data = targetReader(addr)
                    if None != limiter and limiter(data):
                        return
                    if targetValidator(data):
                        yield (addr, path + [offset], data)
                if 0 == (addr % pointerSize):
                    pointer = self.readAddr(addr)
                    if hops > 0 and (0 == (pointer % alignment)) and self.isAddressValid(pointer):
                        for result in self._recursiveFind(targetValidator, pointer, nextSearchLength, pointerSize, targetReader, hops-1, alignment, limiter, path + [offset]):
                            yield result
        except ReadError, e:
            pass

    @staticmethod
    def isInListChecker(target):
        def _isInListChecker(x):
            return x in target
        return _isInListChecker
    @staticmethod
    def isInRangeChecker(target):
        def _isInRangeChecker(x):
            return ((x >= target[0]) and (x < target[1]))
        return _isInRangeChecker
    @staticmethod
    def isEqChecker(target):
        def _isEqChecker(x):
            return x == target
        return _isEqChecker
    @staticmethod
    def stringCaseInsensetiveCmp(target):
        def _stringCaseInsensetiveCmp(x, r):
            return x.replace('\x00', '').lower() == target.lower()
        return _stringCaseInsensetiveCmp

    def recursiveFind( self, target, startAddress, searchLength, hops=1, targetLength=None, alignment=4, limiter=None, isVerbose=False):
        '''
        Description : Main function for recursive search, calls the appropriate function according to the target data type
        Args:
                        target			- target data to be found
                        startAddress	- starting address of the binary data
                        length			- length in bytes of the binary data
                        hops			- depth of recursive hops allowed within data (decreased by recursion) 
                        isVerbose		-  should data be displayed while searcing ?
        
        Return Type : Yields results upon finding addresses which holds the target data
        '''
        if isinstance(target, list):
            targetValidator = RecursiveFind.isInListChecker(target)
        elif isinstance(target, tuple):
            targetValidator = RecursiveFind.isInRangeChecker(target)
        elif isinstance(target, (int, long)):
            targetValidator = RecursiveFind.isEqChecker(target)
        elif isinstance(target, str):
            targetValidator = RecursiveFind.isEqChecker(target)
            targetLength = len(target)
        else:
            targetValidator = target

        if isinstance(target, (list, tuple, int, long)):
            if None == targetLength:
                targetLength = 4
        
            if 8 == targetLength:
                targetReader = self.readQword
            elif 4 == targetLength:
                targetReader = self.readDword
            elif 2 == targetLength:
                targetReader = self.readWord
            elif 1 == targetLength:
                targetReader = self.readByte
            else:
                raise Exception("Target length %s not supported with integer target" % repr(targetLength))

        else:
            targetReader = lambda addr: self.readMemory(addr, targetLength)

        path = []

        pointerSize = self.getPointerSize()
        
        for result in self._recursiveFind(targetValidator, startAddress, searchLength, pointerSize, targetReader, hops, alignment, limiter, path):
            if isVerbose:
                self.printRecursiveFindResult(result)
            yield result

