#
#   DumpBase.py
#
#   DumpBase - Implementation of functions to produce full memory dump
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


from abc import ABCMeta, abstractmethod
from .Interfaces import ReadError
from struct import pack

class DumpBase( object ):
    """ Basic functions to save entier memory snapshot to file """
    DUMP_TYPE_NATIV_DEBUGGING = 0
    DUMP_TYPE_RAW = 1

    @abstractmethod
    def getMemoryMap(self):
        """ Return a dict with infromation about all memory regions.
            dict[baseAddress] = (name, regionSize, regionAttributes) """
        raise NotImplementedError("Pure function call")

    def dumpToFile( self, dumpFile, dumpType=None, comments=None, isVerbose=False ):
        if None == dumpType:
            dumpType = self.DUMP_TYPE_NATIV_DEBUGGING
        if not isinstance(dumpFile, file):
            dumpFile = file(dumpFile, 'wb')
        if self.DUMP_TYPE_NATIV_DEBUGGING == dumpType:
            self._writeDumpHeader(dumpFile)
        memMap = self.getMemoryMap()
        addresses = memMap.keys()
        addresses.sort()
        for addr in addresses:
            regionInfo = memMap[addr]
            regionName = regionInfo[0]
            regionSize = regionInfo[1]
            regionAttrib = regionInfo[2]
            try:
                data = self.readMemory(addr, regionSize)
            except ReadError:
                if isVerbose:
                    print("Failed to read data from address %x to %x" % (addr, addr + regionSize))
                continue
            if self.DUMP_TYPE_NATIV_DEBUGGING == dumpType:
                self._writeAtom(dumpFile, 'REGN', [
                        pack('>Q', addr),
                        pack('>Q', regionSize),
                        pack('>L', regionAttrib),
                        self._makeAtom('NAME', regionName) ] )
                self._writeAtom(dumpFile, 'DATA', data)
            elif self.DUMP_TYPE_RAW == dumpType:
                dumpFile.write(data)
            else:
                raise Exception("Unknown dump format")
        if None != comments and self.DUMP_TYPE_NATIV_DEBUGGING == dumpType:
            self._writeAtom(dumpFile, 'CMNT', comments)

    def _writeDumpHeader(self, dumpFile):
        self._writeAtom(dumpFile, 'NDMD', '')
        self._writeAtom(dumpFile, 'INFO', [
                pack('>L', self.getPointerSize()),
                pack('>L', self.getDefaultDataSize()),
                self.getEndianity() ] )

    def _writeAtom(self, dumpFile, name, data):
        if len(name) != 4:
            raise Exception("Invalid tag name %s" % name)
        totalLength = 0
        if isinstance(data, list):
            for x in data:
                totalLength += len(x)
        else:
            totalLength = len(data)
        dumpFile.write(name)
        dumpFile.write(pack('>Q', totalLength))
        if isinstance(data, list):
            for x in data:
                dumpFile.write(x)
        else:
            dumpFile.write(data)

    def _makeAtom(self, name, data):
        if len(name) != 4:
            raise Exception("Invalid tag name %s" % name)
        allData = ''
        if isinstance(data, list):
            for x in data:
                allData += x
        else:
            allData = data
        result = name + \
                pack('>Q', len(allData)) + \
                allData
        return result




