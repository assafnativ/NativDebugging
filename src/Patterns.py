# Copyright 2010 Assaf Nativ
#    This file is part of Candy.
#
#    Candy is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Candy is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Candy.  If not, see <http://www.gnu.org/licenses/>.

try:
	# Try to use the psycho compiler
    import psyco
    psyco.full()
except ImportError:
    pass

from abc import ABCMeta, abstractmethod
from .Interfaces import MemReaderInterface, ReadError

import sys
from os import linesep
import struct
import datetime
import copy
from types import FunctionType

class SearchContext( object ):
    def __init__(self, perent=None):
        self._perent = perent

    def __repr__(self):
        return self._repr(0)

    def _repr(self, depth):
        result = ''
        items = [x for x in self.__dict__.keys() if \
                (not x.startswith('AddressOf')) and \
                (not x.startswith('OffsetOf')) and \
                (not x.startswith('SizeOf')) and \
                (not x.startswith('_'))]
        items = [(\
                getattr(self, 'AddressOf' + item),
                getattr(self, 'OffsetOf'  + item), \
                getattr(self, 'SizeOf'    + item), \
                item) for item in items]
        items.sort()
        for addr, offset, sizeOf, item in items:
            val = getattr(self, item)
            if isinstance(val, SearchContext):
                result += '\t' * depth
                result += '%-20s@%08x (offset: %08x) size %04x val' % (\
                        item + ':', addr, offset, sizeOf)
                if hasattr(val, '_val'):
                    result += ' %x' % val._val
                result += ':\n'
                result += val._repr(depth+1)
            elif isinstance(val, list):
                result += '\t' * depth
                result += '%-20s@%08x (offset: %08x) size %04x val:\n' % (\
                        item + ':', addr, offset, sizeOf)
                for i, (subAddr, var) in enumerate(val):
                    result += '\t' * depth
                    result += '%8x:           @%08x (offset: %08x) val:' % (\
                            i, subAddr, subAddr - addr)
                    if isinstance(var, SearchContext):
                        result += '\n'
                        result += var._repr(depth+1)
                    else:
                        result += '\t' * depth
                        result += var.__repr__()
                        result += '\n'
            else:
                result += '\t' * depth
                result += '%-20s@%08x (offset: %08x) size %04x val %s\n' % (\
                        item + ':', addr, offset, sizeOf, repr(getattr(self, item)))
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
        
    def getPointerSize(self):
        return self._POINTER_SIZE
    def getDefaultDataSize(self):
        return self._DEFAULT_DATA_SIZE
    def getEndianity(self):
        return self._ENDIANITY
    
    def search(self, pattern, startAddress, lastAddress = 0, context=None):
        if None == context:
            context = SearchContext()
        self.debugContext = context
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
            for x in shape.isValid(self, shape_address, shape_offset, context):
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
        return lambda context, value: sys.stdout.write('%s found @%08x%s'  % (name, getattr(context, 'AddressOf%s' % name), linesep) ) or True
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

class SHAPE( object ):
    def __init__(self, name, place, data, extraCheckFunction=None, fromStart=False):
        striped_name = name.replace('_', '')
        if         name in dir(SearchContext) or \
                0 == len(striped_name) or \
                (not name[0].isalpha) or \
                (not striped_name.isalnum()) or \
                name.startswith('AddressOf') or \
                name.startswith('OffsetOf') or \
                name.startswith('SizeOf') or \
                name.startswith('_'):
            raise Exception("Invalid name for shape")
        self.name       = name
        self.place      = place
        self.iterator   = xrangeWithOffset
        self.procIterator = xrangeFromContext
        self.rangeProc  = None
        self.data       = data
        self.extraCheck = extraCheckFunction
        self.fromStart  = fromStart
        if isinstance(place, tuple):
            self.minOffset = place[0]
            self.maxOffset = place[1]
        elif isinstance(place, (int, long)):
            self.minOffset = 0
            self.maxOffset = place
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
    def __repr__(self):
        return self.name
    def getName(self):
        return self.name
    def getPlace(self):
        return self.place
    def getValidRange(self, start, lastAddress=0, context=None):
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
        if None != self.rangeProc:
            return self.procIterator(self.rangeProc, context, start)
        return self.iterator( self.minOffset, self.maxOffset, self.alignment, start )
    def getData(self):
        return self.data
    def isValid(self, patFinder, address, offset, context):
        value = self.data.readValue(patFinder, address)
        self.currentValue = value
        setattr(context, self.name, value)
        setattr(context, 'AddressOf' + self.name, address)
        setattr(context, 'OffsetOf'  + self.name, offset)
        setattr(context, 'SizeOf'    + self.name, len(self.data))
        for x in self.data.isValid(patFinder, address, value):
            if None != self.extraCheck:
                if True == self.extraCheck(context, value):
                    yield True
            else:
                yield True

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
        self.content    = content
        self.context    = SearchContext()
        DATA_TYPE.__init__(self, **kw)
    def setForSearch(self, patFinder, context):
        self.context._perent = context
        for shape in self.content:
            shape.setForSearch(patFinder, self.context)
    def __len__(self):
        # TODO: add the offsets
        total_size = 0
        for shape in self.content:
            total_size += len(shape.getData())
        return total_size
    def __repr__(self):
        return repr(self.context)
    def readValue(self, patFinder, address):
        return self.context
    def isValid(self, patFinder, address, value):
        for x in patFinder.search(self.content, address, lastAddress=0, context=self.context):
            yield True

class POINTER_TO_STRUCT( POINTER ):
    def __init__(self, content, **kw):
        self.content        = content
        self.context        = SearchContext()
        POINTER.__init__(self, **kw)
    def setForSearch(self, patFinder, context):
        POINTER.setForSearch(self, patFinder, context)
        self.context._perent = context
        for shape in self.content:
            shape.setForSearch(patFinder, self.context)
    def __repr__(self):
        return "Ptr:0x%x\n" + repr(self.context)
    def readValue(self, patFinder, address):
        ptr = patFinder.readAddr(address)
        if patFinder.isAddressValid(ptr):
            # To prevent reads from invalid memory during pattern search
            try:
                patFinder.readByte(ptr)
            except ReadError as e:
                return None
        else:
            return None
        self.context._val = ptr
        return self.context
    def isValid(self, patFinder, address, value):
        if None == value:
            return
        ptr = value._val
        if self.isNullValid and 0 == ptr:
            yield True
        else:
            for x in patFinder.search(self.content, ptr, lastAddress=0, context=self.context):
                yield True

class NUMBER( DATA_TYPE ):
    def __init__(self, value=None, size=None, alignment=None, isSigned=False, endianity='=', **kw):
        self.sizeOfData   = size
        self.alignment    = alignment
        self.value        = value
        self.isSigned     = isSigned
        if endianity not in [">", "<", "="]:
            raise Exception('Invalid endianity (">", "<", "=")')
        self.endianity = endianity
        DATA_TYPE.__init__(self, **kw)
    def setForSearch(self, patFinder, context):
        if '=' == self.endianity:
            self.endianity = patFinder.getEndianity()
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
        if self.endianity == '<':
            result = 'little-endian_' + result
        elif self.endianity == '>':
            result = 'big-endin_' + result
        value = self.value
        if isinstance(value, (int, long)):
            result += 'CONST_VALUE_%d' % value
        elif isinstance(value, tuple):
            result += 'RANGE_FROM_%d_TO_%d' % (value[0], value[1])
        elif isinstance(value, list):
            result += 'ENUM_%s' % repr(value)
        elif None == value:
            result += 'ANYTHING'
        return result
    def readValue(self, patFinder, address):
        result = 0
        if self.endianity == ">":
            for i in range(self.sizeOfData):
                result <<= 8
                result += patFinder.readByte(address + i)
        else:
            for i in range(0, self.sizeOfData):
                result += patFinder.readByte(address + i) << (i * 8)
        if self.isSigned:
            maxPositive = 2 << (self.sizeOfData * 8 - 1)
            if result >= maxPositive:
                result = 0 - ((maxPositive << 1) - result)
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
        elif None == validValue:
            yield True
    def __len__(self):
        return self.sizeOfData
    def getAlignment(self):
        return self.alignment

class CTIME( NUMBER ):
    def __init__(self, value=None, alignment=4, endianity="=", **kw):
        NUMBER.__init__(self, value, size=4, alignment=alignment, isSigned=False, endianity=endianity, **kw)
    def __repr__(self):
        return "CTime"

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
            return struct.unpack(self.endianity + 'Q', patFinder.readMemory(address, 4))[0]
        else:
            return struct.unpack(self.endianity + 'q', patFinder.readMemory(address, 4))[0]
    def __init__(self, value=(0, 0x10000000000000000), isSigned=False, alignment=4, endianity='=', **kw):
        NUMBER.__init__(self, value, size=8, alignment=alignment, isSigned=isSigned, endianity=endianity, **kw)

def IsPrintable(s, isUnicode=False):
    if isUnicode:
        for c in range(len(s)):
            if c % 2 == 0:
                if ord(s[c]) > 0x7f or ord(s[c]) < 0x20:
                    return False
            else:
                if s[c] != '\x00':
                    return False
    else:
        for c in s:
            if ord(c) > 0x7f or ord(c) < 0x20:
                return False
    return True

class BUFFER( DATA_TYPE ):
    def __init__(self, size, **keys):
        self.sizeInBytes = size
        DATA_TYPE.__init__(self, **keys)
    def __repr__(self):
        return 'BUFFER[0x%x]' % self.sizeInBytes
    def __len__(self):
        return self.sizeInBytes
    def readValue(self, patFinder, address):
        return patFinder.readMemory(address, self.sizeInBytes)
    def isValid(self, *arg, **kw):
        yield True

class STRING( DATA_TYPE ):
    NULL_TERM = None
    def __init__(self, size=None, maxSize=0x1000, fixedValue=None, isPrintable=True, isUnicode=False, isCaseSensitive=True, **keys):
        if None != fixedValue:
            size = len(fixedValue)
        elif size > maxSize:
            raise Exception('Invalid size for string')
        self.isPrintable    = isPrintable and (None == fixedValue)
        self.isUnicode      = isUnicode
        self.isCaseSensitive = isCaseSensitive
        self.fixedValue     = fixedValue
        self.maxSize        = maxSize
        self.len            = size
        DATA_TYPE.__init__(self, **keys)
    def __repr__(self):
        if self.NULL_TERM == self.len:
            return '\\0 STRING'
        elif isinstance(self.len, (int, long)):
            return 'STRING[%d]' % self.len
        return 'STRING'
    def __len__(self):
        if None == self.len:
            return 0
        else:
            if self.isUnicode:
                return self.len * 2
            else:
                return self.len
    def readValue(self, patFinder, address):
        try:
            if self.NULL_TERM == self.len:
                result = patFinder.readString(address, maxSize=self.maxSize, isUnicode=self.isUnicode)
            else:
                if self.isUnicode:
                    result = patFinder.readMemory(address, self.len * 2)
                else:
                    result = patFinder.readMemory(address, self.len)
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
                if (self.len * 2) > len(value):
                    return
                for i in range(self.len):
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
    def __init__(self, size, varType, varArgs, varKw={}, **kw):
        self.arraySize = size
        self.varType = varType
        self.array = []
        for i in range(size):
            self.array.append(varType(*varArgs, **varKw))
        DATA_TYPE.__init__(self, **kw)
    def __repr__(self):
        return 'ARRAY_OF_%s[%d]' % (self.varType.__name__, self.arraySize)
    def __len__(self):
        return sum([len(var) for var in self.array])
    def setForSearch(self, patFinder, context):
        for var in self.array:
            var.setForSearch(patFinder, context)
    def readValue(self, patFinder, address):
        result = []
        for var in self.array:
            result.append((address, var.readValue(patFinder, address)))
            address += len(var)
        return result
    def isValid(self, patFinder, address, value, **kw):
        for i, (addr, v) in enumerate(value):
            if len(list(self.array[i].isValid(patFinder, addr, v, **kw))) == 0:
                return
        yield True

