
from abc import ABCMeta
from .Interfaces import MemReaderInterface
from .Utile import makeQwordsList, makeDwordsList

class RecursiveFind( MemReaderInterface ):
    """ Search for offsets using a recurisve method """
    __metaclass__ = ABCMeta

    def _makeAddrList(self, data):
        if 4 == self.getPointerSize():
            return makeQwordsList(data)
        elif 8 == self.getPointerSize():
            return makeDwordsList(data)
        else:
            raise Exception("Invalid pointer size %d" % self.getPointerSize())
    
    def printRecursiveFindResult( self, result ):
        outputString = hex(result[0]) + ' '
        outputString += str(map(hex, result[1])) + ' '
        outputString += str(result[2])
        print outputString

    def _recursiveFindInt( self, target, start_address, length, hops = 1, delta = 0, path = [], isVerbos = False):
        try:
            data = self.readMemory(start_address, length)
        except:
            return
        table_data = self._makeAddrList(data)
        for i in xrange(len(table_data)):
            if table_data[i] + delta >= target and table_data[i] - delta <= target:
                result = (start_address + (i*4), path + [i*4], table_data[i])
                yield result
                if True == isVerbos:
                    self.printRecursiveFindResult( result )
            if hops > 0 and self.isAddressValid(table_data[i]):
                for x in self._recursiveFindInt( target, table_data[i], length, hops - 1, delta, path + [i * 4], isVerbos ):
                    yield x
        return

    def _recursiveFindString( self, target, start_address, length, hops = 1, delta = 0, path = [], isVerbos = False):
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
                yield result
                if True == isVerbos:
                    self.printRecursiveFindResult(result)
                pos += 1
        pos = 0
        lower_target = '\x00'.join(target.lower())
        while pos != -1:
            pos = lower_data.find(lower_target, pos)
            if -1 != pos:
                result = (start_address + pos, path + [pos], self.readString(start_address+pos, True))
                if True == isVerbos:
                    self.printRecursiveFindResult(result)
                pos += 1
        for i in xrange(len(table_data)):
            if hops > 0 and self.isAddressValid(table_data[i]):
                for x in self._recursiveFindString( target, table_data[i], length, hops - 1, delta, path + [i * 4], isVerbos ):
                    yield x
        return

    def _recursiveFindList( self, target, start_address, length, hops = 1, delta = 0, path = [], isVerbos = False):
        try:
            data = self.readMemory(start_address, length)
        except:
            return
        table_data = self._makeAddrList(data)
        for i in xrange(len(table_data)):
            if table_data[i] in target:
                result = (start_address + (i*4), path + [i*4], table_data[i])
                yield result
                if True == isVerbos:
                    self.printRecursiveFindResult(result)
            if hops > 0 and self.isAddressValid(table_data[i]):
                for x in self._recursiveFindList( target, table_data[i], length, hops - 1, delta, path + [i * 4], isVerbos ):
                    yield x
        return

    def _recursiveFindWithMust( self, target, start_address, must_jumps, length, hops = 1, delta = 0, path = []):
        if start_address % 4 != 0:
            raise Exception("Not aligned")
        try:
            data = self.readMemory(start_address, length)
        except:
            return
        table_data = self._makeAddrList(data)
        if type('') == type(target):
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
        for i in xrange(len(table_data)):
            if type(0) == type(target):
                try:
                    addr = self.resolveOffsetsList( start_address, must_jumps[:-1] )[-1]
                    data = m.readAddr(addr + must_jumps[-1])
                    if data + delta >= target and data - delta <= target:
                        yield ((start_address + (i*4), path + must_jumps + [i*4], table_data[i]))
                except:
                    pass
            if hops > 0 and self.isAddressValid(table_data[i]):
                for x in self._recursiveFindWithMust( target, table_data[i], must_jumps, length, hops - 1, delta, path + [i * 4] ):
                    yield x

    def recursiveFind( self, target, start_address, length, hops=1, delta=0, must=None, isVerbos=False):
        path = []
        if start_address % 4 != 0:
            raise Exception("Not aligned")
        if type(must) == type([]):
            if type(target) == type([]):
                raise Exception('List target is not valid with must list')
            for x in self._recursiveFindWithMust(target, start_address, must, length, hops, delta, path):
                yield x
        elif type(target) == type(0):
            for x in self._recursiveFindInt(target, start_address, length, hops, delta, path, isVerbos):
                yield x
        elif type(target) == type(''):
            for x in self._recursiveFindString(target, start_address, length, hops, delta, path, isVerbos):
                yield x
        elif type(target) == type([]):
            for x in self._recursiveFindList(target, start_address, length, hops, delta, path, isVerbos):
                yield x
        else:
            raise Exception("Invalid target")


