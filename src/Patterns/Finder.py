#
#   Finder.py
#
#   Memory Patterns Matcher
#   https://github.com/assafnativ/NativDebugging.git
#   Nativ.Assaf@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#

from abc import ABCMeta, abstractmethod
from ..Interfaces import MemReaderInterface, ReadError

import sys
from os import linesep
import struct
import datetime
import copy
import itertools
from types import FunctionType

class SearchContext( object ):
    def __init__(self, parent=None, root=None):
        self._parent = parent
        if None == root:
            self._root = self
        else:
            self._root = root

    def __repr__(self):
        return self._repr(0)

    def _getItemNames(self):
        return [x for x in self.__dict__.keys() if \
                (not x.startswith('AddressOf')) and \
                (not x.startswith('OffsetOf')) and \
                (not x.startswith('SizeOf')) and \
                (not x.startswith('FootprintOf')) and \
                (not x.startswith('_'))]

    def __len__(self):
        itemNames = self._getItemNames()
        items = [(\
                getattr(self, 'OffsetOf'  + item), \
                getattr(self, 'SizeOf'    + item)) \
                for item in itemNames if hasattr(self, 'SizeOf' + item)]
        if 0 == len(items):
            return 0
        items.sort()
        total = items[-1][0] + items[-1][1]
        return total

    def __invert__(self):
        return self._memorySizeFootprint()
    def __inv__(self):
        return self._memorySizeFootprint()

    def _memorySizeFootprint(self):
        itemNames = self._getItemNames()
        return sum([getattr(self, 'FootprintOf' + name) for name in itemNames])

    def _repr(self, depth, noAddress=False):
        result = ''
        itemNames = self._getItemNames()
        metaItems = [x for x in itemNames if not hasattr(self, 'AddressOf' + x)]
        itemNames = [x for x in itemNames if hasattr(self, 'AddressOf' + x)]
        items = [(\
                getattr(self, 'AddressOf' + item), \
                getattr(self, 'OffsetOf'  + item), \
                getattr(self, 'FootprintOf' + item, -1), \
                item) for item in itemNames]
        items.sort()
        for addr, offset, footprint, item in items:
            val = getattr(self, item)
            result += '\t' * depth
            result += '%-20s' % (item + ':')
            if False == noAddress:
                result += '@%08x ' % addr
            result += '(+%06x) L: %6x val: ' % (offset, footprint)
            if isinstance(val, SearchContext):
                if hasattr(val, '_val'):
                    result += '0x%x' % val._val
                result += ':\n'
                result += val._repr(depth+1, noAddress=noAddress)
            elif isinstance(val, list):
                subAddr = 0
                for i, var in enumerate(val):
                    result += '\n'
                    result += '\t' * (depth + 1)
                    if isinstance(var, SearchContext):
                        result += "Index %4d: " % i
                        result += var._repr(depth, noAddress=noAddress).lstrip()
                    else:
                        result += '%6x: ' % i
                        if False == noAddress:
                            result += '@%08x ' % subAddr
                        result += '(+%06x) val:' % (subAddr - addr)
                        result += '\t' * (depth + 1)
                        result += var.__repr__()
                    subAddr += len(var)
                result += '\n'
            else:
                if isinstance(val, (int, long)):
                    val = hex(val).replace('L', '')
                else:
                    val = repr(val)
                result += '%s\n' % val
        if 0 != len(metaItems):
            result += '\t' * depth
            result += '-' * 10
            result += '\n'
            for item in metaItems:
                val = getattr(self, item)
                if isinstance(val, (int, long)):
                    val = hex(val).replace('L', '')
                else:
                    val = repr(val)
                result += '\t' * depth
                result += '%-20s val %s\n' % (\
                        item + ':', val)

        return result

def CreatePatternsFinder( memReader ):
    if not isinstance(memReader, MemReaderInterface):
        raise Exception("Mem Reader must be of MemReaderInterface type")
    return PatternFinder(memReader)

class PatternFinder( object ):
    def __init__(self, memReader, isSafeSearch=False):
        self.memReader          = memReader
        self.isAddressValid     = memReader.isAddressValid
        self.readMemory         = memReader.readMemory
        self.readByte           = memReader.readByte
        self.readWord           = memReader.readWord
        self.readDword          = memReader.readDword
        self.readQword          = memReader.readQword
        self.readAddr           = memReader.readAddr
        self.readMemory         = memReader.readMemory
        self.readString         = memReader.readString
        self.debugContext       = None
        self._POINTER_SIZE = memReader.getPointerSize()
        self._DEFAULT_DATA_SIZE = memReader.getDefaultDataSize()
        self._ENDIANITY = memReader.getEndianity()
        if '=' == self._ENDIANITY:
            if 'big' == sys.byteorder:
                self._ENDIANITY = '>'
            elif 'little' == sys.byteorder:
                self._ENDIANITY = '<'
            else:
                raise Exception("Unknown endianity %s" % sys.byteorder)
        if isSafeSearch:
            self._search = self._safeSearch
        else:
            self._search = self._unSafeSearch
        self.raiseOnNotFound = False

    def getPointerSize(self):
        return self._POINTER_SIZE
    def getDefaultDataSize(self):
        return self._DEFAULT_DATA_SIZE
    def getEndianity(self):
        return self._ENDIANITY

    def searchOne(self, pattern, startAddress, lastAddress=0, context=None):
        return self.search(pattern, startAddress, lastAddress, context).next()

    def search(self, pattern, startAddress, lastAddress=0, context=None):
        if None == context:
            context = SearchContext()
            context._root = context
        self.debugContext = context
        if not pattern:
            yield context
            return
        for shape in pattern:
            shape.setForSearch(self, context)
        for result in self._search(pattern, startAddress, lastAddress, context):
            yield result

    def _safeSearch(self, pattern, startAddress, lastAddress=0, context=None):
        try:
            for result in self._unSafeSearch(pattern, startAddress, lastAddress, context):
                yield result
        except ReadError:
            return

    def _unSafeSearch(self, pattern, startAddress, lastAddress=0, context=None):
        shape = pattern[0]
        shape_search_range = shape.getValidRange(startAddress, lastAddress, context)
        for shape_address, shape_offset in shape_search_range:
            # Is this the shape we are looking for
            for _ in shape.isValid(self, shape_address, shape_offset, context):
                # Search the next shape if needed
                if len(pattern) > 1:
                    for result in self._search(pattern[1:], startAddress, shape_address + len(shape.getData()), context):
                        yield result
                else:
                    # No more shapes in pattern
                    yield copy.deepcopy(context)
        # Shape not found

    def __genConcatedProc(self, proc1, proc2):
        return lambda context, value: proc1(context, value) and proc2(context, value)
    def __genSetColor(self, displayContext, name, size, color):
        return lambda context, value: displayContext.addColorRanges( \
                (
                    getattr(context, 'AddressOf' + name),
                    max(getattr(context, 'SizeOf' + name), 1),
                    color,
                    name) ) or True
    def __paintPattern(self, depth, pattern, displayContext):
        if 0 == depth:
            return
        for shape in pattern:
            data = shape.getData()
            # Check if recursive
            if isinstance(data, (POINTER_TO_STRUCT, STRUCT)):
                self.__paintPattern(depth-1, data.pattern.content, displayContext)
            if None == shape.extraCheck:
                shape.extraCheck = self.__genSetColor(displayContext, shape.name, '#%06x' % self.color)
            else:
                shape.extraCheck = self.__genConcatedProc(
                        shape.extraCheck,
                        self.__genSetColor(displayContext, shape.name, '#%06x' % self.color) )
            brightness = 0
            while brightness < 0x190:
                self.color += 0x102030
                self.color &= 0xffffff
                brightness = self.color & 0xff
                brightness += (self.color >> 0x08) & 0xff
                brightness += (self.color >> 0x10) & 0xff
    def displaySearch(self, pattern, startAddress, displayContext, maxDepth=3, context=None):
        self.color = 0x2090d0
        pattern = copy.deepcopy(pattern)
        self.__paintPattern(maxDepth, pattern, displayContext)
        return self.search(pattern, startAddress, context=context)
    def __genDisplayText(self, name):
        return lambda context, value: sys.stdout.write('%s found @%08x Offset %08x%s'  % (name, getattr(context, 'AddressOf%s' % name), getattr(context, 'OffsetOf%s' % name), linesep) ) or True
    def __textPattern(self, depth, pattern):
        if 0 == depth:
            return
        for shape in pattern:
            data = shape.getData()
            # Check if recursive
            if isinstance(data, (POINTER_TO_STRUCT, STRUCT)):
                self.__textPattern(depth-1, data.content)
            if None == shape.extraCheck:
                shape.extraCheck = self.__genDisplayText(shape.name)
            else:
                shape.extraCheck = self.__genConcatedProc(
                        shape.extraCheck,
                        self.__genDisplayText(shape.name) )
    def verboseSearch(self, pattern, startAddress, maxDepth=3, context=None):
        pattern = copy.deepcopy(pattern)
        self.__textPattern(maxDepth, pattern)
        return self.search(pattern, startAddress, context=context)


def GetItemsByName( context, name ):
    if hasattr(context, name):
        yield getattr(context, name)
    items = [x for x in context.__dict__.keys() if \
            (not x.startswith('_'))]
    for itemName in items:
        item = getattr(context, itemName)
        if isinstance(item, SearchContext):
            for result in GetItemsByName(item, name):
                yield result

def GetOffsetByName( context, name ):
    return GetItemsByName(context, 'OffsetOf' + name).next()

def GetAddressByName( context, name ):
    return GetItemsByName(context, 'AddressOf' + name).next()

def GetSizeOfByName( context, name ):
    return GetItemsByName(context, 'SizeOf' + name).next()

def GetMemoryFootprintByName( context, name ):
    return GetItemsByName(context, 'FootprintOf' + name).next()

def xrangeWithOffset( start, end, step, addr ):
    pos = start
    while pos <= end:
        yield (pos + addr, pos)
        pos += step

def xrangeFromContext( proc, context, addr ):
    result = proc(context, addr)
    if hasattr(result, 'next'):
        for x in result:
            yield x
    else:
        yield proc(context, addr)

def _genGetRangeProc(name):
    def _getRangeProc(context, addr):
        if hasattr(context, name):
            offset = getattr(context, name)
            yield (addr + offset, offset)
        return
    return _getRangeProc

def isValidShapeName(name):
    striped_name = name.replace('_', '')
    if name in dir(SearchContext) or \
            (not name[0].isalpha) or \
            (not striped_name.isalnum()) or \
            name.startswith('AddressOf') or \
            name.startswith('OffsetOf') or \
            name.startswith('SizeOf') or \
            name.startswith('FootprintOf') or \
            name.startswith('_'):
                return False
    return True

class SHAPE_INTERFACE(object):
    @abstractmethod
    def __init__(self):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")
    def setForSearch(self, *arg):
        return
    def __repr__(self):
        return self.__class__.__name__
    def __len__(self):
        return 0
    def getName(self):
        return self.__class__.__name__
    def getValidRange(self, start, lastAddress=0, context=None):
        return [(lastAddress,0)]
    def getData(self):
        return ''
    @abstractmethod
    def isValid(self, patFinder, address, offset, context):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")

class SHAPE_WITH_NAME(SHAPE_INTERFACE):
    def __init__(self, name):
        if not isValidShapeName(name):
            raise Exception("Invalid shape name (%s)" % name)
        self.name = name
    def __repr__(self):
        return self.name
    def getName(self):
        return self.name

class SHAPE( SHAPE_WITH_NAME ):
    def __init__(self, name, place, data, extraCheckFunction=None, fromStart=False):
        super(SHAPE, self).__init__(name)
        self.place      = place
        self.iterator   = xrangeWithOffset
        self.procIterator = xrangeFromContext
        self.rangeProc  = None
        self.data       = data
        self.extraCheck = extraCheckFunction
        self.fromStart  = fromStart
        if isinstance(place, tuple):
            self.minOffset = place[0]
            if None == place[1]:
                self.maxOffset = place[0]
            else:
                self.maxOffset = place[1]
        elif isinstance(place, (int, long)):
            self.minOffset = 0
            self.maxOffset = place
        elif isinstance(place, str):
            self.rangeProc = _genGetRangeProc(place)
        elif hasattr(place, '__call__') and not hasattr(place, 'mixOffset'):
            self.rangeProc = place
        else:
            self.minOffset = place.minOffset
            self.maxOffset = place.maxOffset
            self.iterator  = place
    def setForSearch(self, patFinder, context):
        self.patFinder = patFinder
        self.data.setForSearch(patFinder, context)
        if isinstance(self.place, tuple) and len(self.place) > 2:
            self.alignment = self.place[2]
        else:
            self.alignment = self.data.getAlignment()
    def getValidRange(self, start, lastAddress=0, context=None):
        if None == self.rangeProc:
            if 0 != lastAddress and False == self.fromStart:
                delta = lastAddress - start
                if 0 != (delta % self.alignment):
                    delta -= delta % (-self.alignment)
                return self.iterator( \
                        self.minOffset + delta,
                        self.maxOffset + delta,
                        self.alignment,
                        start )
            if 0 != (start % self.alignment):
                start -= start % (-self.alignment)
        else:
            return self.procIterator(self.rangeProc, context, start)
        return self.iterator( self.minOffset, self.maxOffset, self.alignment, start )
    def getData(self):
        return self.data
    def isValid(self, patFinder, address, offset, context):
        setattr(context, self.name, self.data.readValue(patFinder, address))
        setattr(context, 'AddressOf' + self.name, address)
        setattr(context, 'OffsetOf'  + self.name, offset)
        found = False
        for _ in self.data.isValid(patFinder, address, getattr(context, self.name)):
            setattr(context, 'SizeOf' + self.name, len(self.data))
            if (not self.extraCheck) or (True == self.extraCheck(context, getattr(context, self.name))):
                setattr(context, 'FootprintOf' + self.name, self.data.memoryFootprint(patFinder, getattr(context, self.name)))
                yield True
                found = True
        if (not found) and patFinder.raiseOnNotFound:
            raise Exception("Shape not found: %r with data type: %r" % (self.name, self.data))

    def details(self):
        if hasattr(self, 'minOffset'):
            minOffset = hex(self.minOffset)
            maxOffset = hex(self.maxOffset)
        else:
            minOffset = "?"
            maxOffset = "?"
        return "%s offset(%s:%s) of type %r" % (self.name, minOffset, maxOffset, self.data)

class ASSERT(SHAPE_INTERFACE):
    def __init__(self, assertFunction):
        self.assertFunction = assertFunction
    def isValid(self, patFinder, address, offset, context):
        if self.assertFunction(patFinder, context):
            yield True

class ASSIGN(SHAPE_WITH_NAME):
    def __init__(self, name, assignFunction):
        super(ASSIGN, self).__init__(name)
        self.assignFunction = assignFunction
    def isValid(self, patFinder, address, offset, context):
        setattr(context, self.name, self.assignFunction(patFinder, context))
        yield True

def _genGetValProc(name):
    def _getValProc(context):
        if '.' in name:
            result = context
            for subAttr in name.split('.'):
                if hasattr(result, subAttr):
                    result = getattr(result, subAttr)
                else:
                    raise Exception("SearchContext has no %s (%s)" % (subAttr, name))
            return result
        elif hasattr(context, name):
            return getattr(context, name)
        return 'default'
    return _getValProc

class DATA_TYPE( object ):
    def __init__(self, desc = ""):
        self.desc = desc

    def __repr__(self):
        if '' != self.desc:
            return '%s %s' % (self.__class__.__name__, self.desc)
        else:
            return self.__class__.__name__

    def setForSearch(self, patFinder, context):
        """
        Used for Shapes that are need to be aware of machine infromation such as pointer size
        """
        pass

    def getAlignment(self):
        return 1

    @abstractmethod
    def __len__(self):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def readValue(self, patFinder, address):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")

    @abstractmethod
    def isValid(self, patFinder, address, value):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")

    def memoryFootprint(self, patFinder, value):
        return len(self)

class ANYTHING( DATA_TYPE ):
    def __init__(self, size = 0, **kw):
        DATA_TYPE.__init__(self, **kw)
        self.datasize = size
    def __len__(self):
        return self.datasize
    def readValue(self, *arg, **kw):
        return None
    def isValid(self, patFinder, address, value):
        yield True

class POINTER( DATA_TYPE ):
    def __init__(self, isNullValid=False, valueRange=None, **kw):
        self.isNullValid = isNullValid
        self.valueRange = valueRange
        DATA_TYPE.__init__(self, **kw)
    def setForSearch(self, patFinder, context):
        self.pointerSize = patFinder.getPointerSize()
    def __len__(self):
        return self.pointerSize
    def getAlignment(self):
        return self.pointerSize
    def readValue(self, patFinder, address):
        return patFinder.readAddr(address)
    def isValid(self, patFinder, address, value):
        if self.isNullValid and 0 == value:
            yield True
        elif self.valueRange != None:
            if  (value >= self.valueRange[0]) and \
                (value < self.valueRange[1]) and \
                (patFinder.isAddressValid(value)):
                    yield True
        elif patFinder.isAddressValid(value):
            yield True

class STRUCT( DATA_TYPE ):
    def __init__(self, content, **kw):
        self.content = content
        self.context = None
        DATA_TYPE.__init__(self, **kw)
    def setForSearch(self, patFinder, context):
        self.context = SearchContext(root=context._root)
        self.context._parent = context
        for shape in self.content:
            shape.setForSearch(patFinder, self.context)
    def __len__(self):
        return len(self.context)
    def memoryFootprint(self, patFinder, value):
        return sum([getattr(value, 'FootprintOf' + s.name) for s in self.content])
    def __repr__(self):
        if self.context:
            return repr(self.context)
        return repr(self.content)
    def readValue(self, patFinder, address):
        self.context._val = address
        return self.context
    def isValid(self, patFinder, address, value):
        for _ in patFinder.search(self.content, address, lastAddress=0, context=value):
            yield True

class POINTER_TO_STRUCT( POINTER ):
    def __init__(self, content, **kw):
        self.content = content
        self.context = None
        POINTER.__init__(self, **kw)
    def setForSearch(self, patFinder, context):
        POINTER.setForSearch(self, patFinder, context)
        self.context = SearchContext(root=context._root)
        self.context._parent = context
        for shape in self.content:
            shape.setForSearch(patFinder, self.context)
    def memoryFootprint(self, patFinder, value):
        total = super(POINTER, self).memoryFootprint(patFinder, value)
        if not value._val:
            return total
        total += sum([getattr(self.context, 'FootprintOf' + s.name) for s in self.content])
        return total
    def __repr__(self):
        if self.context:
            return "Ptr:0x%x\n" + repr(self.context)
        return repr(self.content)
    def readValue(self, patFinder, address):
        ptr = patFinder.readAddr(address)
        self.context._val = ptr
        return self.context
    def isValid(self, patFinder, address, value):
        ptr = value._val
        if self.isNullValid and 0 == ptr:
            yield True
            return

        if not patFinder.isAddressValid(ptr):
            return

        # To prevent reads from invalid memory during pattern search
        try:
            patFinder.readByte(ptr)
        except ReadError:
            return

        if self.valueRange != None:
            if  (ptr < self.valueRange[0]) or \
                (ptr >= self.valueRange[1]):
                    return
        for x in patFinder.search(self.content, ptr, lastAddress=0, context=self.context):
            yield True

class VERBOSE_POINTER_TO_STRUCT( POINTER_TO_STRUCT ):
    def isValid(self, patFinder, address, value):
        if None == value:
            return
        ptr = value._val
        if self.isNullValid and 0 == ptr:
            yield True
        else:
            print hex(ptr)
            print patFinder.memReader.dd(ptr, 0x200)
            for x in patFinder.search(self.content, ptr, lastAddress=0, context=self.context):
                yield True

class DATA_TYPE_FAIL( DATA_TYPE ):
    def __len__(self):
        return 0
    def readValue(self, patFinder, address):
        return None
    def isValid(self, patFinder, address, value):
        return

# At the time of the call to the switch the context must contain all the information needed to decide
class SWITCH( DATA_TYPE ):
    def __init__(self, chooseProc, cases, **kw):
        self.cases = cases
        if isinstance(chooseProc, str):
            self.chooseProc = _genGetValProc(chooseProc)
        else:
            self.chooseProc = chooseProc
        DATA_TYPE.__init__(self, **kw)
    def setForSearch(self, patFinder, context):
        self.parentContext = context
    def __len__(self):
        return len(self.context)
    def memoryFootprint(self, patFinder, value):
        return sum([getattr(value, 'FootprintOf' + s.name) for s in self.currentPattern])
    def __repr__(self):
        return repr(self.context)
    def readValue(self, patFinder, address):
        self.context = SearchContext(self.parentContext._root)
        parentContext = self.parentContext
        self.context._parent = parentContext
        case = self.chooseProc(parentContext)
        if case not in self.cases:
            if "default" in self.cases:
                self.currentPattern = self.cases["default"]
            else:
                self.currentPattern = [SHAPE("CASE_NOT_FOUND", 0, DATA_TYPE_FAIL())]
        else:
            self.currentPattern = self.cases[case]
        for shape in self.currentPattern:
            shape.setForSearch(patFinder, self.context)
        return self.context
    def isValid(self, patFinder, address, value):
        if [] == self.currentPattern:
            yield True
        else:
            for x in patFinder.search(self.currentPattern, address, lastAddress=0, context=self.context):
                yield True

class NUMBER( DATA_TYPE ):
    def __init__(self, value=None, size=None, alignment=None, isSigned=False, endianity='=', **kw):
        self.sizeOfData = size
        if 128 < self.sizeOfData or 0 >= self.sizeOfData:
            raise Exception('Invalid number size ' + repr(self.sizeOfData))
        self.alignment    = alignment
        self.value        = value
        if not isinstance(isSigned, bool):
            raise Exception("Invalid value for isSigned")
        self.isSigned     = isSigned
        if endianity not in [">", "<", "="]:
            raise Exception('Invalid endianity (">", "<", "=")')
        self._endianity = endianity
        DATA_TYPE.__init__(self, **kw)

    def setForSearch(self, patFinder, context):
        if '=' == self._endianity:
            self.endianity = patFinder.getEndianity()
        else:
            self.endianity = self._endianity
        if None == self.sizeOfData:
            self.sizeOfData = patFinder.getDefaultDataSize()
        if None == self.alignment:
            self.alignment = self.sizeOfData

    def __repr__(self):
        sizesNames = {None:'DefaultSize', 1:'BYTE', 2:'WORD', 4:'DWORD', 8:'QWORD'}
        if self.sizeOfData not in sizesNames:
            result = 'NUMBER'
        else:
            result = sizesNames[self.sizeOfData]
        result += '_'
        if self._endianity == '<':
            result = 'little-endian_' + result
        elif self._endianity == '>':
            result = 'big-endin_' + result
        value = self.value
        if isinstance(value, (int, long)):
            result += 'CONST_VALUE_%d' % value
        elif isinstance(value, tuple):
            result += 'RANGE_FROM_%d_TO_%d' % (value[0], value[1])
        elif isinstance(value, list):
            result += 'ENUM_%r' % value
        elif isinstance(value, dict):
            result += 'ENUM_%r' % value
        elif None == value:
            result += 'ANYTHING'
        return result

    def readValue(self, patFinder, address):
        result = 0
        if ">" == self._endianity:
            for i in range(self.sizeOfData):
                result <<= 8
                result += patFinder.readByte(address + i)
        else:
            for i in range(0, self.sizeOfData):
                result += patFinder.readByte(address + i) << (i * 8)
        if self.isSigned:
            maxPositive = 1 << (self.sizeOfData * 8 - 1)
            if result >= maxPositive:
                result -= (maxPositive << 1)
        return result

    def isValid(self, patFinder, address, value):
        validValue = self.value
        if isinstance(validValue, tuple):
            if value < self.value[1] and value >= self.value[0]:
                yield True
        elif isinstance(validValue, (int, long)):
            if value == self.value:
                yield True
        elif isinstance(validValue, list):
            if value in self.value:
                yield True
        elif isinstance(validValue, dict):
            if value in self.value:
                yield True
        elif None == validValue:
            yield True

    def __len__(self):
        return self.sizeOfData

    def getAlignment(self):
        return self.alignment

class SIZE_T( NUMBER ):
    def __init__(self, value=None, alignment=None, endianity='=', **kw):
        self.alignment = alignment
        self.value = value
        self.isSigned = True
        if endianity not in [">", "<", "="]:
            raise Exception('Invalid endianity (">", "<", "=")')
        self._endianity = endianity
        DATA_TYPE.__init__(self, **kw)

    def setForSearch(self, patFinder, context):
        if '=' == self._endianity:
            self.endianity = patFinder.getEndianity()
        else:
            self.endianity = self._endianity
        self.sizeOfData = patFinder.getPointerSize()

    def __repr__(self):
        return 'SIZE_T'

    def getAlignment(self):
        return self.sizeOfData

class FLOAT( NUMBER ):
    def __init__(self, size=None, *arg, **kw):
        if None == size:
            size = 4
        NUMBER.__init__(self, size=size, *arg, **kw)
        if self.sizeOfData == 4:
            self._unpacktype = self._endianity + 'f'
        elif self.sizeOfData == 8:
            self._unpacktype = self._endianity + 'd'
        else:
            raise Exception("Invalid floating point size %d" % self.sizeOfData)
    def __repr__(self):
        sizesNames = {None:'DefaultSize', 4:'FLOAT', 8:'DOUBLE'}
        if self.sizeOfData not in sizesNames:
            result = 'NUMBER'
        else:
            result = sizesNames[self.sizeOfData]
        result += '_'
        if self._endianity == '<':
            result = 'little-endian_' + result
        elif self._endianity == '>':
            result = 'big-endin_' + result
        value = self.value
        if isinstance(value, float):
            result += 'CONST_VALUE_%d' % value
        elif isinstance(value, tuple):
            result += 'RANGE_FROM_%d_TO_%d' % (value[0], value[1])
        elif isinstance(value, list):
            result += 'ENUM_%s' % repr(value)
        elif None == value:
            result += 'ANYTHING'
        return result

    def readValue(self, patFinder, address):
        return struct.unpack(self._unpacktype, patFinder.readMemory(address, self.sizeOfData))[0]

class DOUBLE(FLOAT):
    def __init__(self, *arg, **kw):
        kw['size'] = 8
        FLOAT.__init__(self, *arg, **kw)

class CTIME( NUMBER ):
    def __init__(self, value=None, alignment=4, endianity="=", **kw):
        NUMBER.__init__(self, value, size=4, alignment=alignment, isSigned=False, endianity=endianity, **kw)
    def __repr__(self):
        return "CTime"

class FLAGS( NUMBER ):
    def __init__(self, flagsDesc, checkInvalidFlags=True, **kw):
        self.flagsDesc = flagsDesc
        self.checkInvalidFlags = checkInvalidFlags
        NUMBER.__init__(self, **kw)
    def __repr__(self):
        return "Flags"
    def isValid(self, patFinder, address, value):
        if self.checkInvalidFlags:
            for bitIndex in range(self.sizeOfData * 8):
                mask = 1 << bitIndex
                if (0 != (value & mask)) and mask not in self.flagsDesc:
                    return
        yield True

class BYTE( NUMBER ):
    def readValue(self, patFinder, address):
        if False == self.isSigned:
            return patFinder.readByte(address)
        else:
            value = patFinder.readByte(address)
            if value >= 0x80:
                return 0 - (0x100 - value)
            else:
                return value
    def __init__(self, value=(0,0x100), isSigned=False, alignment=1, endianity='=', **kw):
        NUMBER.__init__(self, value, size=1, alignment=alignment, isSigned=isSigned, endianity=endianity, **kw)

class WORD( NUMBER ):
    def readValue(self, patFinder, address):
        if False == self.isSigned:
            return struct.unpack(self.endianity + 'H', patFinder.readMemory(address, 2))[0]
        else:
            return struct.unpack(self.endianity + 'h', patFinder.readMemory(address, 2))[0]
    def __init__(self, value=(0, 0x10000), isSigned=False, alignment=2, endianity='=', **kw):
        NUMBER.__init__(self, value, size=2, alignment=alignment, isSigned=isSigned, endianity=endianity, **kw)

class DWORD( NUMBER ):
    def readValue(self, patFinder, address):
        if False == self.isSigned:
            return struct.unpack(self.endianity + 'L', patFinder.readMemory(address, 4))[0]
        else:
            return struct.unpack(self.endianity + 'l', patFinder.readMemory(address, 4))[0]
    def __init__(self, value=(0, 0x100000000), isSigned=False, alignment=4, endianity='=', **kw):
        NUMBER.__init__(self, value, size=4, alignment=alignment, isSigned=isSigned, endianity=endianity, **kw)

class QWORD( NUMBER ):
    def readValue(self, patFinder, address):
        if False == self.isSigned:
            return struct.unpack(self.endianity + 'Q', patFinder.readMemory(address, 8))[0]
        else:
            return struct.unpack(self.endianity + 'q', patFinder.readMemory(address, 8))[0]
    def __init__(self, value=(0, 0x10000000000000000), isSigned=False, alignment=4, endianity='=', **kw):
        NUMBER.__init__(self, value, size=8, alignment=alignment, isSigned=isSigned, endianity=endianity, **kw)

def IsPrintable(s, isUnicode=False):
    if 0 == len(s):
            return True
    if isUnicode:
        try:
            s.decode('utf-16le')
        except UnicodeDecodeError:
            return False
    else:
        if '\0' == s[-1]:
            s = s[:-1]
        for c in s:
            if ord(c) > 0x7f or ord(c) < 0x20:
                return False
    return True

class BUFFER( DATA_TYPE ):
    def __init__(self, size, **keys):
        if isinstance(size, str):
            self.sizeInBytes = _genGetValProc(size)
        else:
            self.sizeInBytes = size
        DATA_TYPE.__init__(self, **keys)
    def __repr__(self):
        return 'BUFFER[0x%x]' % self.sizeInBytes
    def __len__(self):
        if hasattr(self.sizeInBytes, '__call__'):
            result = self.sizeInBytes(self.searchContext)
        else:
            result = self.sizeInBytes
        return result
    def setForSearch(self, patFinder, context):
        self.searchContext = context
    def readValue(self, patFinder, address):
        length = self.sizeInBytes
        if hasattr(length, '__call__'):
            length = length(self.searchContext)
        return patFinder.readMemory(address, length)
    def isValid(self, *arg, **kw):
        yield True

class STRING( DATA_TYPE ):
    NULL_TERM = None
    def __init__(self, size=None, maxSize=0x1000, fixedValue=None, isPrintable=True, isUnicode=False, isCaseSensitive=True, **keys):
        if isinstance(fixedValue, str):
            size = len(fixedValue)
        if isinstance(size, (int, long)) and size > maxSize:
            raise Exception('Invalid size for string')
        self.isPrintable    = isPrintable and (None == fixedValue)
        self.isUnicode      = isUnicode
        self.isCaseSensitive = isCaseSensitive
        self.fixedValue     = fixedValue
        self.maxSize        = maxSize
        if isinstance(size, str):
            size = _genGetValProc(size)
        self.length = size
        DATA_TYPE.__init__(self, **keys)

    def __repr__(self):
        if self.NULL_TERM == self.length:
            return '\\0 STRING'
        elif isinstance(self.length, (int, long)):
            return 'STRING[%d]' % self.length
        return 'STRING'

    def __len__(self):
        if None == self.length:
            return 0
        elif hasattr(self.length, '__call__'):
            length = self.length(self.searchContext)
        else:
            length = self.length
        if self.isUnicode:
            return length * 2
        return length

    def setForSearch(self, patFinder, context):
        self.searchContext = context

    def readValue(self, patFinder, address):
        try:
            if self.NULL_TERM == self.length:
                return patFinder.readString(address, maxSize=self.maxSize, isUnicode=self.isUnicode)
            elif hasattr(self.length, '__call__'):
                length = self.length(self.searchContext)
            else:
                length = self.length
            if 0 == length:
                result = ''
            elif self.isUnicode:
                result = patFinder.readMemory(address, length * 2)
            else:
                result = patFinder.readMemory(address, length)
        except ReadError as e:
            #print 'FIXED_SIZE_STRING read overflow'
            return ''
        return result

    def isValid(self, patFinder, address, value):
        if self.isPrintable:
            if False == IsPrintable( value, isUnicode=self.isUnicode ):
                return
        if None != self.fixedValue:
            if self.isUnicode:
                if (self.length * 2) > len(value):
                    return
                for i in range(self.length):
                    if self.isCaseSensitive:
                        if value[i*2] != self.fixedValue[i]:
                            return
                        if value[i*2 + 1] != '\x00':
                            return
                    else:
                        if value[i*2].lower() != self.fixedValue[i].lower():
                            return
                        if value[i*2 + 1] != '\x00':
                            return
            else:
                if self.isCaseSensitive and value != self.fixedValue:
                    return
                elif (not self.isCaseSensitive) and value.lower() != self.fixedValue.lower():
                    return
        yield True

class ARRAY( DATA_TYPE ):
    def __init__(self, count, varType, varArgs=None, varKw=None, isZeroSizeValid=True, **kw):
        """
        count, varType, varArgs=None, varKw=None, isZeroSizeValid=True

        Multi occurrences of a SHAPE
        Var type is a SHAPE type such as DWORD, NUMBER, STRING. Note this is not an instance
        but the class type. The instance would be created by the ARRAY.
        If the init of the SHAPE type requires args / key words, one can set them using the:
            varArgs - List of args
            varKw - Dictunary args
        """
        if isinstance(count, str):
            self.arraySize = _genGetValProc(count)
        else:
            self.arraySize = count
        if None == varArgs:
            varArgs = []
        if None == varKw:
            varKw = {}
        self.varType = varType
        self.varArgs = varArgs
        self.varKw = varKw
        self.array = []
        self.contexts = []
        self.isZeroSizeValid = isZeroSizeValid
        DATA_TYPE.__init__(self, **kw)

    def __repr__(self):
        return 'ARRAY_OF_%s[%d]' % (self.varType.__name__, self.arraySize)
    def __len__(self):
        return sum([len(var) for var in self.array])

    def memoryFootprint(self, patFinder, values):
        return sum([val.FootprintOfItem for val in values])

    def setForSearch(self, patFinder, context):
        self.parentContext = context
        for var in self.array:
            var.setForSearch(patFinder, context)

    def readValue(self, patFinder, address):
        if isinstance(self.arraySize, (int, long)):
            arraySize = self.arraySize
        else:
            arraySize = self.arraySize(self.parentContext)
        self.array = []
        self.contexts = []
        for i in range(arraySize):
            self.array.append(self.varType(*self.varArgs, **self.varKw))
            newContext = SearchContext(root=self.parentContext._root)
            newContext._parent = self.parentContext
            self.contexts.append(newContext)
        return self.contexts

    def recursiveIsValid(self, patFinder, address, contexts, contextIndex=0):
        if (contextIndex == len(contexts)) or (0 == len(contexts)):
            yield True
            return
        dt = self.array[contextIndex]
        ctx = contexts[contextIndex]
        dt.setForSearch(patFinder, ctx)
        value = dt.readValue(patFinder, address)
        for _ in dt.isValid(patFinder, address, value):
            ctx.AddressOfItem = address
            ctx.OffsetOfItem = 0
            ctx.SizeOfItem = len(dt)
            ctx.FootprintOfItem = dt.memoryFootprint(patFinder, value)
            for _ in self.recursiveIsValid(patFinder, address + len(dt), contexts, contextIndex+1):
                yield True

    def isValid(self, patFinder, address, values):
        for _ in self.recursiveIsValid(patFinder, address, values):
            yield True
        if 0 == len(values) and isZeroSizeValid:
            yield True

