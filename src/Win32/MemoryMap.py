#
#   MemoryMap.py
#
#   MemoryMap - A class that holds a map of memory pages / blocks
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


class MemoryMap( object ):
    def __init__(self, memoryMap, reader, atomSize=4):
        self._memoryMap = memoryMap
        self._reader = reader
        self.READ_ATTRIBUTES_MASK       = reader.READ_ATTRIBUTES_MASK
        self.WRITE_ATTRIBUTES_MASK      = reader.WRITE_ATTRIBUTES_MASK
        self.EXECUTE_ATTRIBUTES_MASK    = reader.EXECUTE_ATTRIBUTES_MASK
        self.ALL_ATTRIBUTES_MASK        = reader.ALL_ATTRIBUTES_MASK
    
    def getAddressInfo(self, x):
        for addr, block in self._memoryMap.items():
            if x >= addr and x < (addr + block[1]):
                return MemoryBlockInfo(addr, block)
        return None

    def filteredMap(self, attributesMask=None, nameStartsWith=None, nameContains=None):
        if None == attributesMask:
            attributesMask = self.ALL_ATTRIBUTES_MASK
        if None != nameStartsWith:
            nameStartsWith = nameStartsWith.lower()
        if None != nameContains:
            nameContains = nameContains.lower()
        for addr, block in self._memoryMap.items():
            if block[2] & attributesMask:
                if None != nameStartsWith and not block[0].lower().startswith(nameStartsWith):
                    continue
                if None != nameContains and not nameContains in block[0].lower():
                    continue
                yield MemoryBlockInfo(addr, block)

    def __iter__(self):
        for addr, block in self._memoryMap.items():
            yield MemoryBlockInfo(addr, block)
        

class MemoryBlockInfo(object):
    def __init__(self, address, length, name='', attributes=0):
        self.address = address
        if tuple == type(length):
            block = length
            self.length     = block[1]
            self.name       = block[0]
            self.attributes = block[2]
        else:
            self.length = length
            self.name = name
            self.attributes = attributes

    def __repr__(self):
        return 'Address: 0x{0:x}\nLength: 0x{1:x}\nName: {2:s}\nAttributes: 0x{3:x}'.format(
                self.address, 
                self.length, 
                self.name, 
                self.attributes)

    def __len__(self):
        return self.length

