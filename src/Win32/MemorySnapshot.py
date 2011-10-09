#
#   MemorySnapshot.py
#
#   MemorySnapshot
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

# Maybe in the future I shell split this class into a MemorySnapshot and MemoryMap classes
# MemorySnapshot would be platform depended, while MemoryMap won't
class MemorySnapshot( object ):
    READ_ATTRIBUTES_MASK    = 0xee # [0x20, 0x40, 0x80, 0x02, 0x04, 0x08]
    WRITE_ATTRIBUTES_MASK   = 0xcc # [0x40, 0x80, 0x04, 0x08]
    EXECUTE_ATTRIBUTES_MASK = 0xf0 # [0x10, 0x20, 0x40, 0x80]
    def __init__(self, memoryMap, reader, atomSize=4, memory={}):
        self._memoryMap = memoryMap
        self._memory = memory
        self._atomSize = atomSize
        self._reader = reader
    
    def getAddressInfo(self, x):
        for addr, block in self._memoryMap.iteritems():
            if x > addr and x < (addr + block[1]):
                return MemoryBlockInfo(addr, block[1], block[0], block[2])
        return None
    
    def readAllWritableMemory(self):
        self.readAllMemoryWithAttributes(self.WRITE_ATTRIBUTES_MASK)
    def readAllReadableMemory(self):
        self.readAllMemoryWithAttributes(self.READ_ATTRIBUTES_MASK)
    def readAllExecutableMemory(self):
        self.readAllMemoryWithAttributes(self.EXECUTE_ATTRIBUTES_MASK)

    def readAllMemoryWithAttributes(self, attributesMask):
        for addr, block in self._memoryMap.iteritems():
            if (block[2] & attributesMask):
                try:
                    self._memory[addr] = self._reader.readMemory(addr, block[1])
                except WindowsError, e:
                    continue

    def filterMemoryOldWithNew(self, comperator, atomSize=None):
        newMemory = {}
        if None == atomSize:
            atomSize = self._atomSize
        for addr, block in self._memory.iteritems():
            try:
                newBlockAddress = addr
                newBlockSize = 0
                for offset in xrange(0, len(block), atomSize):
                    if not comperator( \
                            self._reader.readMemory(addr + offset, atomSize), \
                            block[offset:offset+atomSize] ):
                        if newBlockSize > 0:
                            newMemory[newBlockAddress] = \
                                self._reader.readMemory(newBlockAddress, newBlockSize)
                        newBlockAddress = addr + offset + atomSize
                        newBlockSize = 0
                    else:
                        newBlockSize += atomSize
            except WindowsError, e:
                continue
            if newBlockSize > 0:
                newMemory[newBlockAddress] = \
                    self._reader.readMemory(newBlockAddress, newBlockSize)
        self._memory = newMemory

    def filterMemoryWithConst(self, comperator, const, atomSize=None):
        newMemory = {}
        if None == atomSize:
            atomSize = self._atomSize
        for addr, block in self._memory.iteritems():
            try:
                for offset in xrange(0, len(block), atomSize):
                    data = self._reader.readMemory(addr + offset, atomSize)
                    if comperator(
                            data,
                            const):
                        newMemory[addr + offset] = data
            except WindowsError, e:
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
        keys = self._memory.keys()
        keys.sort()
        result = ''
        for i, x in enumerate(keys[:MAX_DISPLAY]):
            result += '%d: 0x%08x: %s\n' % (i, x, self._memory[x].encode('hex'))
        if len(keys) > MAX_DISPLAY:
            result += '\nMore'
        return result

    def __getitem__(self, index):
        keys = self._memory.keys()
        keys.sort()
        if isinstance(index, slice):
            newMemory = {}
            for key in keys[index]:
                newMemory[key] = self._memory[key]
            return MemorySnapshot(self._memoryMap, self._reader, atomSize=self._atomSize, memory=newMemory)
        return keys[index]

    def __delitem__(self, index):
        keys = self._memory.keys()
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
        if not isinstance(other, MemorySnapshot):
            raise TypeError()
        otherKeys = other._memory.keys()
        selfKeys = self._memory.keys()
        newMemory = deepcopy(self._memory)
        for key in otherKeys:
            if comperator(key, selfKeys):
                if key in selfKeys:
                    if len(other._memory[key]) > len(self._memory[key]):
                        newMemory[key] = other._memory[key]
                else:
                    newMemory[key] = other._memory[key]
        return MemorySnapshot(self._memoryMap, self._reader, atomSize=self._atomSize, memory=newMemory)

    def _operatorRemove(self, other, comperator):
        if not isinstance(other, MemorySnapshot):
            raise TypeError()
        newMemory = {}
        otherKeys = other._memory.keys()
        for key in self._memory.keys():
            if comperator(key, otherKeys):
                newMemory[key] = self._memory[key]
        return MemorySnapshot(self._memoryMap, self._reader, atomSize=self._atomSize, memory=newMemory)


class MemoryBlockInfo(object):
    def __init__(self, address, length, name, attributes):
        self.address = address
        self.length = length
        self.name = name
        self.attributes = attributes
    def __repr__(self):
        return 'Address: 0x%x\nLength: 0x%x\nName: %s\nAttributes: 0x%x' % (
                self.address, 
                self.length, 
                self.name, 
                self.attributes)
