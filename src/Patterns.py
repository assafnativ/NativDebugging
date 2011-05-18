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
    import psyco
    psyco.full()
except ImportError:
    pass

from .Interfaces import MemReaderInterface

import sys
import struct
import datetime
import copy

class MemoryReadError( Exception ):
    pass

class SearchContext( object ):
    def __init__(self):
        pass
    def __repr__(self):
        result = ''
        for item in self.__dict__.keys():
            if item.startswith('AddressOf'):
                continue
            elif item.startswith('OffsetOf'):
                continue
            elif item.startswith('__'):
                continue
            result += '%-20s@%08x (offset: %08x) value=%s\n' % (item + ':', self.__dict__['AddressOf'+item], self.__dict__['OffsetOf'+item], `self.__dict__[item]`)
        return result

def CreatePatternsFinder( memReader ):
    if not isinstance(memReader, MemReaderInterface):
        raise Exception("Mem Reader must be of MemReaderInterface type")
    return PatternFinder(memReader)

class PatternFinder( object ):
    def __init__(self, memReader):
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
        self._POINTER_SIZE = memReader.getPointerSize()
        self._DEFAULT_DATA_SIZE = memReader.getDefaultDataSize()
        self._ENDIANITY = memReader.getEndianity()

    def getPointerSize(self):
        return self._POINTER_SIZE
    def getDefaultDataSize(self):
        return self._DEFAULT_DATA_SIZE
    def getEndianity(self):
        return self._ENDIANITY
    
    def search(self, pattern, startAddress, lastAddress = 0, context=None):
        if None == context:
            context = SearchContext()
        self.context = context
        for shape in pattern:
            shape.setForSearch(self)
        for result in self._search(pattern, startAddress, lastAddress, context):
            yield result

    def _search(self, pattern, startAddress, lastAddress = 0, context=None):
        shape = pattern[0]
        shape_search_range = shape.getValidRange(startAddress, lastAddress)
        for shape_address, shape_offset in shape_search_range:
            # Is this the shape we are looking for
            for x in shape.isValid(self, shape_address, shape_offset):
                # Search the next shape if needed
                if len(pattern) > 1:
                    for result in self._search(pattern[1:], startAddress, shape_address + shape.getData().size(), context):
                        yield result
                else:
                    # No more shapes in pattern
                    yield copy.deepcopy(self.context)
        # Shape not found

    def __genConcatedProc(self, proc1, proc2):
        return lambda context, value: proc1(context, value) and proc2(context, value)
    def __genSetColor(self, displayContext, name, size, color):
        return lambda context, value: displayContext.addColorRanges((context.__dict__['AddressOf%s' % name], size, color, name)) or True
    def __paintPattern(self, depth, pattern, displayContext):
        if 0 == depth:
            return
        for shape in pattern:
            data = shape.getData()
            size = data.size()
            # Check if recursive
            if isinstance(data, POINTER_TO_STRUCT) and depth > 1:
                if isinstance(data.pattern, STRUCT):
                    self.__paintPattern(depth-1, data.pattern.content, displayContext)
            elif 0 != size:
                if None == shape.extraCheck:
                    shape.extraCheck = self.__genSetColor(displayContext, shape.name, size, '#%06x' % self.color)
                else:
                    shape.extraCheck = self.__genConcatedProc(
                            shape.extraCheck, 
                            self.__genSetColor(displayContext, shape.name, size, '#%06x' % self.color) )
                brightness = 0
                while brightness < 0x190:
                    self.color += 0x102030
                    self.color &= 0xffffff
                    brightness = self.color & 0xff
                    brightness += (self.color >> 0x08) & 0xff
                    brightness += (self.color >> 0x10) & 0xff
    def displaySearch(self, pattern, startAddress, displayContext, maxDepth=1, context=None):
        self.color = 0x2090d0
        pattern = copy.deepcopy(pattern)
        self.__paintPattern(maxDepth, pattern, displayContext)
        return self.search(pattern, startAddress, context=context)
    def __genDisplayText(self, name):
        return lambda context, value: sys.stdout.write('%s found @%08x' % (name, context.__dict__['AddressOf%s' % name]) ) or True
    def __textPattern(self, depth, pattern):
        if 0 == depth:
            return
        for shape in pattern:
            data = shape.getData()
            size = data.size()
            # Check if recursive
            if isinstance(data, STRUCT) and depth > 1:
                self.__paintPattern(depth-1, data.content, displayContext)
            elif isinstance(data, POINTER_TO_STRUCT) and depth > 1:
                self.__paintPattern(depth-1, [data.pattern], displayContext)
            elif 0 != size:
                if None == shape.extraCheck:
                    shape.extraCheck = self.__genDisplayText(shape.name)
                else:
                    shape.extraCheck = self.__genConcatedProc(
                            shape.extraCheck, 
                            self.__genDisplayText(shape.name) )
    def verbosSearch(self, pattern, startAddress, maxDepth=1, context=None):
        pattern = copy.deepcopy(pattern)
        self.__textPattern(maxDepth, pattern)
        return self.search(pattern, startAddress, context=context)
           

def GetOffsetByName( result, name ):
    return result.__dict__['OffsetOf' + name]

def xrangeWithOffset( start, end, step, addr ):
    pos = start
    while pos <= end:
        yield (pos + addr, pos)
        pos += step

class SHAPE( object ):
    def __init__(self, name, place, data, extraCheckFunction=None, fromStart=False):
        striped_name = name.replace('_', '')
        if         name in dir(SearchContext) or \
                0 == len(striped_name) or \
                (not name[0].isalpha) or \
                (not striped_name.isalnum()) or \
                name.startswith('AddressOf') or \
                name.startswith('OffsetOf'):
            raise Exception("Invalid name for shape")
        self.name     = name
        self.place    = place
        self.iterator = xrangeWithOffset
        self.data     = data
        self.extraCheck = extraCheckFunction
        self.fromStart = fromStart
        if type(place) == tuple:
            self.minOffset = place[0]
            self.maxOffset = place[1]
        elif type(place) == int or type(place) == long:
            self.minOffset = 0
            self.maxOffset = place
        else:
            self.minOffset = place.minOffset
            self.maxOffset = place.maxOffset
            self.iterator = place
    def setForSearch(self, patFinder):
        self.data.setForSearch(patFinder)
        if type(self.place) == tuple and len(self.place) > 2:
            self.alignment = self.place[2]
        else:
            self.alignment = self.data.getAlignment()
    def __repr__(self):
        return self.name
    def getName(self):
        return self.name
    def getPlace(self):
        return self.place
    def getValidRange(self, start, lastAddress=0):
        if 0 != lastAddress and False == self.fromStart:
            delta = lastAddress - start
            if 0 != (delta % self.alignment):
                delta += (self.alignment - (delta % self.alignment))
            if 0 != (start % self.alignment):
                start += (self.alignment - (start % self.alignment))
            return self.iterator( self.minOffset + delta, self.maxOffset + delta, self.alignment, start )
        else:
            if 0 != (start % self.alignment):
                start += (self.alignment - (start % self.alignment))
            return self.iterator( self.minOffset, self.maxOffset, self.alignment, start )
    def getData(self):
        return self.data
    def isValid(self, patFinder, address, offset):
        value = self.data.readValue(patFinder, address)
        self.currentValue = value
        context = patFinder.context
        context.__dict__[self.name] = value
        context.__dict__['AddressOf' + self.name] = address
        context.__dict__['OffsetOf' + self.name] = offset
        for x in self.data.isValid(patFinder, address, value):
            if None != self.extraCheck:
                if True == self.extraCheck(context, value):
                    yield True
            else:
                yield True

# TODO:
#class DEBUG_SHAPE( SHAPE ):

class dataType( object ):
    def __init__(self, desc = ""):
        self.desc = desc
    def __repr__(self):
        if '' != self.desc:
            return '%s %s' % (self.__class__.__name__, self.desc)
        else:
            return self.__class__.__name__
    def setForSearch(self, patFinder):
        """
        Used for Shapes that are need to be aware of machine infromation such as pointer size
        """
        pass
    def size(self):
        raise Exception("Pure")
    def getAlignment(self):
        return 1

class ANYTHING( dataType ):
    def __init__(self, size = 0, **kw):
        dataType.__init__(self, **kw)
        self.datasize = size
    def size(self):
        return self.datasize
    def readValue(self, *arg, **kw):
        return None
    def isValid(self, *arg, **kw):
        yield True

class POINTER( dataType ):
    def __init__(self, isNullValid=False, valueRange=None, **kw):
        self.isNullValid = isNullValid
        self.valueRange = valueRange
        dataType.__init__(self, **kw)
    def setForSearch(self, patFinder):
        self.pointerSize = patFinder.getPointerSize()
    def size(self):
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

class STRUCT( dataType ):
    def __init__(self, content, **kw):
        self.content    = content
        dataType.__init__(self, **kw)
    def size(self):
        # TODO: add the offsets
        total_size = 0
        for shape in self.content:
            total_size += shape.getData().size()
        return total_size
    def readValue(self, patFinder, address):
        return None
    def isValid(self, patFinder, address, value):
        for x in patFinder.search(self.content, address, lastAddress=0, context=patFinder.context):
            yield True

class POINTER_TO_STRUCT( POINTER ):
    def __init__(self, pattern, isNullValid = False, **kw):
        self.pattern        = pattern
        self.isNullValid    = isNullValid
        dataType.__init__(self, **kw)
    def readValue(self, patFinder, address):
        return patFinder.readAddr(address)
    def isValid(self, patFinder, address, value):
        if self.isNullValid and 0 == value:
            yield True
        elif patFinder.isAddressValid(value):
            content = self.pattern.readValue(patFinder, value)
            for x in self.pattern.isValid(patFinder, value, content):
                yield True

class NUMBER( dataType ):
    def __init__(self, value=None, size=None, alignment=None, isSigned=False, endianity='=', **kw):
        self.sizeOfData   = size
        self.alignment    = alignment
        self.value        = value
        self.valueType    = type(value)
        self.isSigned    = isSigned
        if endianity not in [">", "<", "="]:
            raise Exception('Invalid endianity (">", "<", "=")')
        self.endianity = endianity
        dataType.__init__(self, **kw)
    def setForSearch(self, patFinder):
        if '=' == self.endianity:
            endianity = patFinder.getEndianity()
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
        valueType = type(self.value)
        if valueType == int or valueType == long:
            result += 'CONST_VALUE_%d' % self.value
        elif valueType == tuple:
            result += 'RANGE_FROM_%d_TO_%d' % (self.value[0], self.value[1])
        elif valueType == list:
            result += 'ENUM_%s' % `self.value`
        elif self.value == None:
            result += 'ANYTHING'
        return result
    def readValue(self, patFinder, address):
        result = 0
        if self.endianity == ">":
            for i in xrange(self.sizeOfData):
                result <<= 8
                result += patFinder.readByte(address + i)
        else:
            for i in xrange(0, self.sizeOfData):
                result += patFinder.readByte(address + i) << (i * 8)
        if self.isSigned:
            maxPositive = 2 << (self.sizeOfData * 8 - 1)
            if result >= maxPositive:
                result = 0 - ((maxPositive << 1) - result)
        return result
    def isValid(self, patFinder, address, value):
        if self.valueType == tuple:
            if value < self.value[1] and value >= self.value[0]:
                yield True
        elif self.valueType == int or self.valueType == long:
            if value == self.value:
                yield True
        elif self.valueType == list:
            if value in self.value:
                yield True
        elif self.valueType == type(None):
            yield True
    def size(self):
        return self.sizeOfData
    def getAlignment(self):
        return self.alignment

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
        for c in xrange(len(s)):
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

class BUFFER( dataType ):
    def __init__(self, size, **keys):
        self.sizeInBytes = size
        dataType.__init__(self, **keys)
    def __repr__(self):
        return 'BUFFER[0x%x]' % self.sizeInBytes
    def size(self):
        return self.sizeInBytes
    def readValue(self, patFinder, address):
        return patFinder.readMemory(address, self.sizeInBytes)
    def isValid(self, *arg, **kw):
        yield True

NULL_TERM = None
class STRING( dataType ):
    def __init__(self, size=None, maxSize=0x1000, fixedValue=None, isPrintable=True, isUnicode=False, isCaseSensitive=True, **keys):
        if None != fixedValue:
            size = len(fixedValue)
        elif size > maxSize:
            raise Exception('Invalid size for string')
        self.isPrintable    = isPrintable
        self.isUnicode      = isUnicode
        self.isCaseSensitive = isCaseSensitive
        self.fixedValue     = fixedValue
        self.maxSize        = maxSize
        self.len            = size
    def __repr__(self):
        if NULL_TERM == self.len:
            return '\\0 STRING'
        elif type(self.len) == int:
            return 'STRING[%d]' % self.len
        return 'STRING'
    def size(self):
        if None == self.len:
            return 0
        else:
            if self.isUnicode:
                return self.len * 2
            else:
                return self.len
    def readValue(self, patFinder, address):
        try:
            if NULL_TERM == self.len:
                result = patFinder.readString(address, maxSize=self.maxSize, isUnicode=self.isUnicode)
            else:
                if self.isUnicode:
                    result = patFinder.readMemory(address, self.len * 2)
                else:
                    result = patFinder.readMemory(address, self.len)
        except MemoryReadError, e:
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
                for i in xrange(self.len):
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

class ARRAY( dataType ):
    def __init__(self, size, var, **kw):
        self.arraySize = size
        self.var = var
        dataType.__init__(self, **kw)
    def __repr__(self):
        return 'ARRAY_OF_%s[%d]' % (self.var.__class__.__name__,self.arraySize)
    def size(self):
        return self.var.size() * self.arraySize
    def readValue(self, patFinder, address):
        result = []
        for i in xrange(self.arraySize):
            result.append(self.var.readValue(patFinder, address))
            address += self.var.size()
        return result
    def isValid(self, patFinder, address, value, **kw):
        for v in value:
            if len(list(self.var.isValid(patFinder, address, v, **kw))) == 0:
                return
        yield True

