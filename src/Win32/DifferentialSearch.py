#
#   DifferentialSearch.py
#
#   DifferentialSearch - A class that helps performaing a differential search of memory
#   https://svn3.xp-dev.com/svn/nativDebugging/
#   Nativ.Assaf+debugging@gmail.com
#   Copyright (C) 2011  Assaf Nativ
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

from struct import unpack
from copy import deepcopy
from ..Interfaces import ReadError

class DifferentialSearch( object ):
    READ_ALL_WRITABLE_MEMORY    = 1
    READ_ALL_READABLE_MEMORY    = 2
    READ_ALL_EXECUTABLE_MEMORY  = 4
    READ_ALL_MEMORY             = 8
    def __init__(self, memMap, reader, searchIn=READ_ALL_WRITABLE_MEMORY, atomSize=4, memory=None):
        self._memoryMap = memMap
        self._atomSize = atomSize
        self._reader = reader
        self._readMemory = reader.readMemory
        if None == memory:
            self._memory = {}
            readAttributesMask = 0
            if 0 != (searchIn & self.READ_ALL_READABLE_MEMORY):
                readAttributesMask |= memMap.READ_ATTRIBUTES_MASK
            if 0 != (searchIn & self.READ_ALL_WRITABLE_MEMORY):
                readAttributesMask |= memMap.WRITE_ATTRIBUTES_MASK
            if 0 != (searchIn & self.READ_ALL_EXECUTABLE_MEMORY):
                readAttributesMask |= memMap.EXECUTE_ATTRIBUTES_MASK
            if 0 != (searchIn & self.READ_ALL_MEMORY):
                readAttributesMask |= memMap.ALL_ATTRIBUTES_MASK
            self.readAllMemoryWithAttributes(readAttributesMask)
        else:
            self._memory = memory

    def readAllMemoryWithAttributes(self, attributesMask):
        for block in self._memoryMap.filteredMap(attributesMask):
            try:
                self._memory[block.address] = self._readMemory(block.address, block.length)
            except (WindowsError, ReadError):
                continue

    def filterMemoryOldWithNew(self, comperator, atomSize=None):
        newMemory = {}
        if None == atomSize:
            atomSize = self._atomSize
        for addr, data in self._memory.items():
            try:
                newBlockAddress = addr
                newBlockSize = 0
                for offset in range(0, len(data), atomSize):
                    if not comperator( \
                            self._readMemory(addr + offset, atomSize), \
                            data[offset:offset+atomSize] ):
                        if newBlockSize > 0:
                            newMemory[newBlockAddress] = \
                                self._readMemory(newBlockAddress, newBlockSize)
                        newBlockAddress = addr + offset + atomSize
                        newBlockSize = 0
                    else:
                        newBlockSize += atomSize
            except (WindowsError, ReadError) as e:
                continue
            if newBlockSize > 0:
                newMemory[newBlockAddress] = \
                    self._readMemory(newBlockAddress, newBlockSize)
        self._memory = newMemory

    def filterMemoryWithConst(self, comperator, const, atomSize=None):
        newMemory = {}
        if None == atomSize:
            atomSize = self._atomSize
        for addr, data in self._memory.items():
            try:
                for offset in range(0, len(data), atomSize):
                    newData = self._readMemory(addr + offset, atomSize)
                    if comperator(
                            newData,
                            const):
                        newMemory[addr + offset] = newData
            except (WindowsError, ReadError) as e:
                continue
        self._memory = newMemory
    
    def removeChangedMemory(self):
        self.filterMemoryOldWithNew(bytes.__eq__)
    def removeUnchangedMemory(self):
        self.filterMemoryOldWithNew(bytes.__ne__)
        
    def searchUInt32(self, x):
        if x > 0xffffffff or x < 0:
            raise Exception("Uint32 out of range")
        self.filterMemoryWithConst(
            (lambda y, z: unpack('=L', y)[0] == z), 
            x,
            4)
    def searchInt32(self, x):
        if x > 0x7fffffff or x < -0x80000000:
            raise Exception("Int32 out of range")
        self.filterMemoryWithConst(
            (lambda y, z: unpack('=l', y)[0] == z),
            x,
            4)

    def searchUint16(self, x):
        if x > 0xffff or x < 0:
            raise Exception("Uint16 out of range")
        self.filterMemoryWithConst(
            (lambda y, z: unpack('=H', y)[0] == z), 
            x,
            2)
            
    def searchInt16(self, x):
        if x > 0x7fff or x < 8000:
            raise Exception("Int16 out of range")
        self.filterMemoryWithConst(
            (lambda y, z: unpack('=h', y)[0] == z), 
            x,
            2)

    def searchUint8(self, x):
        if x > 0xff or x < 0:
            raise Exception("Uint8 out of range")
        self.filterMemoryWithConst(
            (lambda y, z: unpack('=B', y)[0] == z), 
            x,
            1)
            
    def searchInt8(self, x):
        if x > 0x7f or x < 80:
            raise Exception("Int8 out of range")
        self.filterMemoryWithConst(
            (lambda y, z: unpack('=b', y)[0] == z), 
            x,
            1)

    def __len__(self):
        return len(self._memory)

    def __repr__(self):
        MAX_DISPLAY = 0x40
        keys = list(self._memory.keys())
        keys.sort()
        result = ''
        for i, x in enumerate(keys[:MAX_DISPLAY]):
            result += '%d: 0x%08x: %s\n' % (i, x, self._memory[x].encode('hex'))
        if len(keys) > MAX_DISPLAY:
            result += '\nMore'
        return result

    def __getitem__(self, index):
        keys = list(self._memory.keys())
        keys.sort()
        if isinstance(index, slice):
            newMemory = {}
            for key in keys[index]:
                newMemory[key] = self._memory[key]
            return DifferentialSearch(self._memoryMap, self._reader, atomSize=self._atomSize, memory=newMemory)
        return keys[index]

    def __delitem__(self, index):
        keys = list(self._memory.keys())
        keys.sort()
        if isinstance(index, slice):
            for key in keys[index]:
                del self._memory[key]
        else:
            del self._memory[keys[index]]

    def __sub__(self, other):
        return self._operatorRemove(other, (lambda x,y:not list.__contains__(x, y)))

    def __and__(self, other):
        return self._operatorRemove(other, list.__contains__)

    def __or__(self, other):
        return self._operatorAdd(other, (lambda x,y:True))

    def __add__(self, other):
        return self._operatorAdd(other, (lambda x,y:True))

    def __xor__(self, other):
        return self._operatorAdd(other, (lambda x,y:not list.__contains__(x, y)))

    def _operatorAdd(self, other, comperator):
        if not isinstance(other, DifferentialSearch):
            raise TypeError()
        otherKeys = list(other._memory.keys())
        selfKeys = list(self._memory.keys())
        newMemory = deepcopy(self._memory)
        for key in otherKeys:
            if comperator(key, selfKeys):
                if key in selfKeys:
                    if len(other._memory[key]) > len(self._memory[key]):
                        newMemory[key] = other._memory[key]
                else:
                    newMemory[key] = other._memory[key]
        return DifferentialSearch(self._memoryMap, self._reader, atomSize=self._atomSize, memory=newMemory)

    def _operatorRemove(self, other, comperator):
        if not isinstance(other, DifferentialSearch):
            raise TypeError()
        newMemory = {}
        otherKeys = list(other._memory.keys())
        for key in list(self._memory.keys()):
            if comperator(key, otherKeys):
                newMemory[key] = self._memory[key]
        return DifferentialSearch(self._memoryMap, self._reader, atomSize=self._atomSize, memory=newMemory)


