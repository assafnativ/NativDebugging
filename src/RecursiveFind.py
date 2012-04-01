
from abc import ABCMeta
from .Interfaces import MemReaderInterface
from .Utile import makeQwordsList, makeDwordsList

class RecursiveFind( MemReaderInterface ):
    """ Search for offsets using a recurisve method """
    __metaclass__ = ABCMeta

    def _makeAddrList(self, data):
        '''
        Description : Divides data into a list of addresses
        Args:
                        data - binary data to be converted
        Return Value : list of addresses (cell size is according to pointer size)
        '''
        if 8 == self.getPointerSize():
            return makeQwordsList(data)
        elif 4 == self.getPointerSize():
            return makeDwordsList(data)
        else:
            raise Exception("Invalid pointer size %d" % self.getPointerSize())
    
    def printRecursiveFindResult( self, result ):
        '''
        Description : prints a result returned from a binary search in a human friendly way
        Args:
                        result - list/tuple which holds the result to be displayed (starting address, offsets to data, name ??)
        Return Value : None, just prints the string
        '''
        print(('0x{0:x}\t{1:s}\t"{2:s}"'.format(result[0], ''.join(['0x{0:x}, '.format(x) for x in result[1]]), str(result[2]))))

    def _recursiveFindInt( self, target, start_address, length, hops = 1, delta = 0, path = [], isVerbose = False):
        '''
        Description : Searches for an integer in a binary data , tries to find data recursively by jumping into addresses within  data
        Args:
                        target			- target int to be found
                        start_address	- starting address of the binary data
                        length			- length in bytes of the binary data
                        hops			- depth of recursive hops allowed within data (decreased by recursion)
                        delta			- allowed delta from target integer
                        path			- path of offsets the search is currently in
                        isVerbose		- display data while searching ?
        Return Value : yields results (iterator) upon finding target int
        '''
        try:
            data = self.readMemory(start_address, length)
        except:
            return
        table_data = self._makeAddrList(data)
        for i in range(len(table_data)):
            offset = i * self.getPointerSize()
            if table_data[i] + delta >= target and table_data[i] - delta <= target:
                result = (start_address + offset, path + [offset], table_data[i])
                if True == isVerbose:
                    self.printRecursiveFindResult( result )
                yield result
            if hops > 0 and self.isAddressValid(table_data[i]):
                for x in self._recursiveFindInt( target, table_data[i], length, hops - 1, delta, path + [offset], isVerbose ):
                    yield x
        return

    def _recursiveFindString( self, target, start_address, length, hops=1, delta = 0, path = [], isVerbose = False):
        '''
        Description: Searches for a string in a binary data , also tries to find string recursively by jumping into address within data
        Args:
                        target			- target string to be searched
                        start_address	- starting address of the binary data
                        length			- llength in bytes of the binary data
                        hops 			- depth of recursive hops allowed within data (decreased by recursion)
                        delta			- doesn't mean anything here (TODO : delete it ?)
                        path			- list of offsets found for data
                        isVerbose		- should data be displayed while searcing ?
                        
        Return Value : yields results (iterator) upon finding target string
        Remarks : Assumes the string is in ASCII , tries to match the string in UNICODE as well
        '''
        try:
            data = self.readMemory(start_address, length)
        except:
            return
        table_data = self._makeAddrList(data)
        pos = 0
        lower_data = data.lower()
        lower_target = target.lower()
        while pos != -1:
            pos = lower_data.find(lower_target, pos)
            if -1 != pos:
                result = (start_address + pos, path + [pos], self.readString(start_address+pos))
                if True == isVerbose:
                    self.printRecursiveFindResult(result)
                yield result
                pos += 1
        pos = 0
        lower_target = '\x00'.join(target.lower())
        while pos != -1:
            pos = lower_data.find(lower_target, pos)
            if -1 != pos:
                if True == isVerbose:
                    self.printRecursiveFindResult(result)
                result = (start_address + pos, path + [pos], self.readString(start_address+pos, True))
                yield result
                pos += 1
        if hops > 0:
            for i in range(len(table_data)):
                if self.isAddressValid(table_data[i]):
                    for x in self._recursiveFindString( target, table_data[i], length, hops - 1, delta, path + [i * self.getPointerSize()], isVerbose ):
                        yield x
        return

    def _recursiveFindList( self, target, start_address, length, hops = 1, delta = 0, path = [], isVerbose = False):
        '''
        Description : Searches for any value from a given list within a binary data, also tries to find string recursively by jumping into address within data
        Args:
                        target			- target list to be searched
                        start_address	- starting address of the binary data
                        length			- length in bytes of the binary data
                        hops			- depth of recursive hops allowed within data (decreased by recursion)
                        delta 			- doesn't mean anything here (TODO : delete it ?)
                        path			- list of offsets found for data
                        isVerbose		- should data be displayed while searcing ?
        Return Value : yields all addresses which hold one of the lists items.
        '''
        try:
            data = self.readMemory(start_address, length)
        except:
            return
        table_data = self._makeAddrList(data)
        for i in range(len(table_data)):
            offset = i * self.getPointerSize()
            if table_data[i] in target:
                result = (start_address + offset, path + [offset], table_data[i])
                if True == isVerbose:
                    self.printRecursiveFindResult(result)
                yield result
            if hops > 0 and self.isAddressValid(table_data[i]):
                for x in self._recursiveFindList( target, table_data[i], length, hops - 1, delta, path + [offset], isVerbose ):
                    yield x
        return

    def _recursiveFindWithMust( self, target, start_address, must_jumps, length, hops = 1, delta = 0, path = []):
        '''
        Description : Searches for a data (int,long or string) inside a binary data, data must be pointed by a given set of offsets
        Args:
                        target			- target data to be found
                        start_address	- starting address of the binary data
                        must_jumps		- list of offsets to data
                        length			- length in bytes of the binary data
                        hops 			- depth of recursive hops allowed within data (decreased by recursion) 
                        delta			- delta allowed from target (used only when the target is from int type)
                        path			- list of offsets found for data
                        
        Return Value : yields all the addresses which holds path to the target data
        '''
        if start_address % 4 != 0:
            raise Exception("Not aligned")
        try:
            data = self.readMemory(start_address, length)
        except:
            return
        table_data = self._makeAddrList(data)
        if isinstance(target, str):
            try:
                addr = self.resolveOffsetsList(start_address, must_jumps[:-1])[-1]
                data = self.readMemory(addr + must_jumps[-1], len(target) * 2)
            except:
                data = ''
            if '' != data:
                lower_data = data.lower()
                lower_target = target.lower()
                pos = lower_data.find(lower_target)
                if -1 != pos:
                    yield ((start_address + pos, path + must_jumps + [pos], self.readString(start_address+pos)))
                    pos += 1
                lower_target = '\x00'.join(target.lower())
                pos = lower_data.find(lower_target)
                if -1 != pos:
                    yield ((start_address + pos, path + must_jumps + [pos], self.readString(start_address+pos, True)))
                    pos += 1
        for i in range(len(table_data)):
            offset = i * self.getPointerSize()
            if isinstance(target, (int, long)):
                try:
                    addr = self.resolveOffsetsList( start_address, must_jumps[:-1] )[-1]
                    data = m.readAddr(addr + must_jumps[-1])
                    if data + delta >= target and data - delta <= target:
                        yield ((start_address + offset, path + must_jumps + [offset], table_data[i]))
                except:
                    pass
            if hops > 0 and self.isAddressValid(table_data[i]):
                for x in self._recursiveFindWithMust( target, table_data[i], must_jumps, length, hops - 1, delta, path + [offset] ):
                    yield x

    def recursiveFind( self, target, start_address, length, hops=1, delta=0, must=None, isVerbose=False):
        '''
        Description : Main function for recursive search, calls the appropriate function according to the target data type
        Args:
                        target			- target data to be found
                        start_address	- starting address of the binary data
                        length			- length in bytes of the binary data
                        hops			- depth of recursive hops allowed within data (decreased by recursion) 
                        delta			- delta allowed from target (int datatype only)
                        must			- list of offsets which must be found (with the same order) in order to get to target
                        isVerbose		-  should data be displayed while searcing ?
        
        Return Type : Yields results upon finding addresses which holds the target data
        '''
        path = []
        if start_address % 4 != 0:
            raise Exception("Not aligned")
        if isinstance(must, tuple):
            if isinstance(target, list):
                raise Exception('List target is not valid with must list')
            for x in self._recursiveFindWithMust(target, start_address, must, length, hops, delta, path):
                if True == isVerbose:
                    self.printRecursiveFindResult(x)
                yield x
        elif isinstance(target, (int, long)):
            for x in self._recursiveFindInt(target, start_address, length, hops, delta, path, isVerbose):
                yield x
        elif isinstance(target, str):
            for x in self._recursiveFindString(target, start_address, length, hops, delta, path, isVerbose):
                yield x
        elif isinstance(target, list):
            for x in self._recursiveFindList(target, start_address, length, hops, delta, path, isVerbose):
                yield x
        else:
            raise Exception("Invalid target")


