#
#   MemoryReader.py
#
#   MemoryReader - Remote process memory inspection python module
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

from ..Interfaces import MemWriterInterface
from .MemReaderBaseWin import *
from ..GUIDisplayBase import *

from .Win32Structs import *
from .Win32Utile import *
import sys
import struct
from pefile import *

PAGE_SIZE = 0x1000

def attach(targetProcessId):
    return MemoryReader(targetProcessId)

class MemoryReader( MemReaderBaseWin, MemWriterInterface, GUIDisplayBase ):
    def __init__( self, target_process_id ):
        MemReaderBase.__init__(self)
        adjustDebugPrivileges()
        self._processId = target_process_id
        self._openProcess( target_process_id )
        temp_void_p = c_void_p(1)
        temp_void_p.value -= 2
        self._is_win64 = (temp_void_p.value > (2**32))
        if self._is_win64:
            self._POINTER_SIZE = 8
        else:
            self._POINTER_SIZE = 4
        self._DEFAULT_DATA_SIZE = 4
        self._mem_map = None
        self._READ_ATTRIBUTES       = [1, 2, 4, 6, 9, 11, 12, 14, 17, 19, 20, 22, 25, 27, 28, 30]
        self._WRITE_ATTRIBUTES      = [4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31]
        self._EXECUTE_ATTRIBUTES    = [2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31]
        self._cache = [(0, [])] * (0x80000000 >> 12)

    def __del__( self ):
        self._closeProcess()

    def _closeProcess( self ):
        CloseHandle( self._process )

    def _openProcess( self, target_pid ):
        bytes_read = c_uint(0)
        self._process = OpenProcess( 
                win32con.PROCESS_QUERY_INFORMATION | 
                win32con.PROCESS_VM_READ | 
                win32con.PROCESS_VM_WRITE |
                win32con.PROCESS_VM_OPERATION |
                win32con.PROCESS_DUP_HANDLE,
                0,
                target_pid )

    def deprotectMem( self, addr, size ):
        old_protection = c_uint(0)
        VirtualProtectEx( self._process, addr, size, win32con.PAGE_EXECUTE_READWRITE, byref(old_protection) )

    def readAddr( self, addr ):
        result = c_void_p(0)
        bytes_read = c_uint(0)
        read_result = ReadProcessMemory( self._process, addr, byref(result), self._POINTER_SIZE, byref(bytes_read) )
        if 0 == read_result:
            raise WinError()
        if None == result.value:
            return 0
        return result.value

    def readQword( self, addr ):
        result = c_ulonglong(0)
        bytes_read = c_uint(0)
        read_result = ReadProcessMemory( self._process, addr, byref(result), 8, byref(bytes_read) )
        if 0 == read_result:
            raise WinError()
        return result.value

    def readDword( self, addr ):
        result = c_uint(0)
        bytes_read = c_uint(0)
        read_result = ReadProcessMemory( self._process, addr, byref(result), 4, byref(bytes_read) )
        if 0 == read_result:
            raise WinError()
        return result.value

    def readWord( self, addr ):
        result = c_uint(0)
        bytes_read = c_uint(0)
        read_result = ReadProcessMemory( self._process, addr, byref(result), 2, byref(bytes_read) )
        if 0 == read_result:
            raise WinError()
        return result.value

    def readByte( self, addr ):
        result = c_uint(0)
        bytes_read = c_uint(0)
        read_result = ReadProcessMemory( self._process, addr, byref(result), 1, byref(bytes_read) )
        if 0 == read_result:
            raise WinError()
        return result.value

    def readMemory( self, addr, length ):
        result = ARRAY(c_char, length)('\x00')
        bytes_read = c_uint(0)
        read_result = ReadProcessMemory( self._process, addr, byref(result), sizeof(result), byref(bytes_read) )
        if 0 == read_result:
            raise WinError()
        return result.raw

    def readString( self, addr, maxSize=None, isUnicode=False ):
        result = ''
        bytes_read = c_uint(0)
        char = c_uint(0)
        bytesCounter = 0

        while True:
            if False == isUnicode:
                try:
                    ReadProcessMemory( self._process, addr + bytesCounter, byref(char), 1, byref(bytes_read) )
                except WindowsError:
                    return result
                bytesCounter += 1
            else:
                try:
                    ReadProcessMemory( self._process, addr + bytesCounter, byref(char), 2, byref(bytes_read) )
                except WindowsError:
                    return result
                bytesCounter += 2
            if 1 < char.value and char.value < 0x80:
                result += chr(char.value)
            else:
                return result
            if None != maxSize and bytesCounter > maxSize:
                return result

    def writeAddr( self, addr, data ):
        if 4 == self._POINTER_SIZE:
            self.writeDword(addr, data)
        elif 8 == self._POINTER_SIZE:
            self.writeQword(addr, data)
        else:
            raise Exception("Unknown pointer size")

    def writeQword( self, addr, data ):
        if isinstance(data, int) or isinstance(data, long):
            data = struct.pack('<Q', data)
        data_to_write = c_buffer(data, 8)
        bytes_written = c_uint(0)
        WriteProcessMemory( self._process, addr, data_to_write, 8, byref(bytes_written) )

    def writeDword( self, addr, data ):
        if isinstance(data, int) or isinstance(data, long):
            data = struct.pack('<L', data)
        data_to_write = c_buffer(data, 4)
        bytes_written = c_uint(0)
        WriteProcessMemory( self._process, addr, data_to_write, 4, byref(bytes_written) )

    def writeWord( self, addr, data ):
        if isinstance(data, int) or isinstance(data, long):
            data = struct.pack('<H', data)
        data_to_write = c_buffer(data, 2)
        bytes_written = c_uint(0)
        WriteProcessMemory( self._process, addr, data_to_write, 2, byref(bytes_written) )

    def writeByte( self, addr, data ):
        if isinstance(data, int) or isinstance(data, long):
            data = struct.pack('<B', data)
        data_to_write = c_buffer(data, 1)
        bytes_written = c_uint(0)
        WriteProcessMemory( self._process, addr, data_to_write, 1, byref(bytes_written) )

    def writeMemory( self, addr, data ):
        #data_to_write = ARRAY(c_char, len(data))(tuple(data))
        data_to_write = c_buffer(data)
        bytes_written = c_uint(0)
        WriteProcessMemory( self._process, addr, data_to_write, len(data), byref(bytes_written) )
        return bytes_written.value

    def findMemBlock( self, addr ):
        if None == self._mem_map:
            self.getMemoryMapWithQuery()
        size = len(self._mem_map_keys)
        if self._mem_map_keys[size // 2] > addr:
            block_start = self._findMemBlockStart( addr, self._mem_map_keys[:size // 2], size // 2 )
        else:
            block_start = self._findMemBlockStart( addr, self._mem_map_keys[size // 2:], size // 2 )
        block = self._mem_map[block_start]
        if addr > (block_start + block[1]):
            return None
        else:
            return block
        
    def _findMemBlockStart( self, addr, keys, size ):
        if size == 1:
            return keys[0]
        mid = size // 2
        if keys[mid] > addr:
            return self._findMemBlockStart( addr, keys[:mid], mid )
        else:
            return self._findMemBlockStart( addr, keys[mid:], mid )

    def isAddressWritable( self, addr ):
        block = self.findMemBlock( addr )
        if None == block:
            return False
        if block[2] in self._WRITE_ATTRIBUTES:
            return True
        return False

    def isAddressReadable( self, addr ):
        block = self.findMemBlock( addr )
        if None == block:
            return False
        if block[2] in self._READ_ATTRIBUTES:
            return True
        return False

    def isAddressExecuatable( self, addr ):
        block = self.findMemBlock( addr )
        if None == block:
            return False
        if block[2] in self._EXECUTE_ATTRIBUTES:
            return True
        return False

    def isAddressValid( self, addr ):
        result = c_uint(0)
        bytes_read = c_uint(0)
        #if addr % 4 != 0:
        #   return False
        returncode = ReadProcessMemory( self._process, addr, byref(result), 1, byref(bytes_read) )
        if 0 != returncode and 1 == bytes_read.value:
            return True
        return False

###     block = self.findMemBlock(addr)
###     if None == block:
###         return False
###     return True

    def getMemoryMapWithQuery( self ):
        if self._is_win64:
            raise Excpetion("Not supported on x64")
        result = {}

        # Enum modules sections and sizes
        modules = ARRAY( c_void_p, PAGE_SIZE )(0)
        bytes_written = c_uint(0)
        EnumProcessModules( self._process, byref(modules), sizeof(modules), byref(bytes_written) )
        num_modules = bytes_written.value / sizeof(c_void_p(0))
        for module_iter in xrange(num_modules):
            module_name = ARRAY( c_char, 1000 )('\x00')
            GetModuleBaseName( self._process, modules[module_iter], byref(module_name), sizeof(module_name) )
            module_name = module_name.value
            module_cut_name = module_name.replace('\x00', '')
            module_info = MODULEINFO(0)
            GetModuleInformation( self._process, modules[module_iter], byref(module_info), sizeof(module_info) )
            module_base = module_info.lpBaseOfDll
            if module_base & 0xfff != 0:
                raise Exception("Module not page aligned")
            result[module_base] = (module_cut_name, module_info.SizeOfImage, 0)
            # Get the sections
            module_bin = self.readMemory(module_base, PAGE_SIZE) #module_info.SizeOfImage)
            parsed_pe = PE(data=module_bin, fast_load=True)
            for section in parsed_pe.sections:
                section_addr = (section.VirtualAddress & 0xfffff000l) + module_base
                section_size = section.SizeOfRawData
                # Algin to end of page
                if 0 == section_size:
                    section_size = PAGE_SIZE
                elif (section_size & 0xfff) != 0:
                    section_size += PAGE_SIZE - (section_size & 0xfff)
                # Append to list
                result[section_addr] = (module_cut_name + section.Name.replace('\x00', ''), section_size, 1)
            
        # Get all other memory and attributes of pages
        memory_map = ARRAY( c_uint, 0x80000 )(0)
        QueryWorkingSet( self._process, byref(memory_map), sizeof(memory_map) )
        number_of_pages = memory_map[0]
        for page in memory_map[1:1+number_of_pages]:
            addr = page & (0xfffff000l)
            attrib = page & 0xfff
            # We have no intrest in kernel pages
            if addr > 0x80000000l:
                continue
            # Check if page found
            page_found = False
            page_already_set = False
            for block_start in result.keys():
                if addr >= block_start and addr < (block_start + result[block_start][1]):
                    page_found = True
                    if addr != block_start:
                        page_already_set = True
                    else:
                        page_already_set = False
                        module_name = result[block_start][0]
                        module_size = result[block_start][1]
                        break
            if True == page_already_set:
                continue
            if True == page_found:
                result[addr] = (module_name, module_size, attrib)
            else:
                result[addr] = ("", PAGE_SIZE, attrib)

        # Concat blocks
        keys = result.keys()
        keys.sort()
        pos = 1
        while pos < len(keys):
            prev = result[keys[pos-1]]
            cur = result[keys[pos]]
            if  prev[0] == cur[0] and \
                prev[2] == cur[2] and \
                keys[pos-1] + prev[1] == keys[pos]:

                result[keys[pos-1]] = (cur[0], cur[1] + prev[1], cur[2])
                del result[keys[pos]]
                keys = keys[:pos] + keys[pos+1:]
            else:
                pos += 1

        self._mem_map = result.copy()
        self._mem_map_keys = result.keys()
        self._mem_map_keys.sort()
        return result

    def getMemoryMap( self ):
        if self._is_win64:
            raise Exception( "Not supported on x64" )
        result = []
        one_byte = c_uint(0)
        bytes_read = c_uint(0)
        for i in range( 0l, 0x80000000l, PAGE_SIZE ):
            read_result = ReadProcessMemory( self._process, i, byref(one_byte), 1, byref(bytes_read) )
            if 0 != read_result:
                yield( ("", i, PAGE_SIZE) )

    def getMemorySnapshot( self ):
        result = []
        memMap = self.getMemoryMapWithQuery()
        for addr in memMap.keys():
            if self.isAddressWritable(addr):
                result.append((addr, self.readMemory(addr, memMap[addr][1])))
        return result

    def searchInMemory( self, target, searchRange=None, isCaseSensitive=True, searchUnicode=False ):
        if self._is_win64:
            return "Not supported on x64"
        result = []

        if None == searchRange:
            searchRange = self.getMemoryMap()

        if False == isCaseSensitive:
            target = target.lower()
        if isinstance(target, str):
            last_block = ''
            for block in searchRange:
                try:
                    data = last_block + self.readMemory(block[1], block[2])
                except WindowsError:
                    print "Can't read from %08x" % block[1]
                    continue
                if False == isCaseSensitive:
                    data = data.lower()
                pos = data.find(target)
                while -1 != pos:
                    result.append(pos + block[1] - len(last_block))
                    pos = data.find(target, pos+1)
                last_block = data[-(len(target) - 1):]
            if False == searchUnicode:
                return result
            target = '\x00'.join(target)
            last_block = ''
            for block in searchRange:
                try:
                    data = last_block + self.readMemory(block[1], block[2])
                except WindowsError:
                    print "Can't read from %08x" % block[1]
                    continue
                if False == isCaseSensitive:
                    data = data.lower()
                pos = data.find(target)
                while -1 != pos:
                    result.append(pos + block[1] - len(last_block))
                    pos = data.find(target, pos+1)
                last_block = data[-(len(target) - 1):]
        elif isinstance(target, int) or isinstance(target, long):
            target = struct.pack('<L', target)
            for block in searchRange:
                try:
                    data = self.readMemory(block[1], block[2])
                except WindowsError:
                    print "Can't read from %08x" % block[1]
                    continue
                pos = data.find(target)
                while -1 != pos:
                    result.append(pos + block[1])
                    pos = data.find(target, pos+1)

        return result

    def removeChangedMemory( self, snapshot ):
        result = []
        for block in snapshot:
            addr = block[0]
            offset = 0
            try:
                for byte in block[1]:
                    if self.readByte(addr + offset) == ord(byte):
                        result.append((addr + offset, byte))
                    offset += 1
            except WindowsError, e:
                continue

        return result
    
    def removeUnchangedMemory( self, snapshot ):
        result = []
        for block in snapshot:
            addr = block[0]
            offset = 0
            try:
                for byte in block[1]:
                    newByte = self.readByte(addr + offset)
                    if newByte != ord(byte):
                        result.append((addr + offset, chr(newByte)))
                    offset += 1
            except WindowsError, e:
                continue
        return result
            
        
    def searchBinInAllMemory( self, target, isCaseSensitive = True ):
        if self._is_win64:
            return "Not supported on x64"

        results = []

        if isinstance(target, int) or isinstance(target, long):
            target = struct.pack('<L', target)
        elif False == isCaseSensitive:
            target = target.lower()
        firstByteTarget = target[:1]

        pos = 0l
        while pos < 0x8000000l:
            if 0 == (pos & 0xffffff):
                print '.',
            try:
                data = self.readMemory( pos, len(target) )
                if False == isCaseSensitive:
                    data = data.lower()
                if data == target:
                    results.append(pos)
            except WindowsError:
                pos += PAGE_SIZE - (pos % PAGE_SIZE)
                continue
            pos += 1

        return results

    def getPointerSize(self):
        return self._POINTER_SIZE

    def getDefaultDataSize(self):
        return self._DEFAULT_DATA_SIZE


