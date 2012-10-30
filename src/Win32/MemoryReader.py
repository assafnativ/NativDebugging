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

from ..Interfaces import MemWriterInterface, ReadError
from .MemReaderBaseWin import *
from ..GUIDisplayBase import *

from .MemoryMap import *
from .Win32Structs import *

try:
    import distorm3
    IS_DISASSEMBLER_FOUND = True
except ImportError as e:
    IS_DISASSEMBLER_FOUND = False
import sys
import struct

def attach(targetProcessId):
    return MemoryReader(targetProcessId)

class MemoryReader( MemReaderBaseWin, MemWriterInterface, GUIDisplayBase ):
    PAGE_SIZE       = 0x1000
    PAGE_SIZE_MASK  = 0x0fff
    READ_ATTRIBUTES_MASK    = 0xee # [0x20, 0x40, 0x80, 0x02, 0x04, 0x08]
    WRITE_ATTRIBUTES_MASK   = 0xcc # [0x40, 0x80, 0x04, 0x08]
    EXECUTE_ATTRIBUTES_MASK = 0xf0 # [0x10, 0x20, 0x40, 0x80]
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
        #self._READ_ATTRIBUTES       = [1, 2, 4, 6, 9, 11, 12, 14, 17, 19, 20, 22, 25, 27, 28, 30]
        #self._WRITE_ATTRIBUTES      = [4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31]
        #self._EXECUTE_ATTRIBUTES    = [2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31]
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
            raise ReadError(addr)
        if None == result.value:
            return 0
        return result.value

    def readQword( self, addr ):
        result = c_ulonglong(0)
        bytes_read = c_uint(0)
        read_result = ReadProcessMemory( self._process, addr, byref(result), 8, byref(bytes_read) )
        if 0 == read_result:
            raise ReadError(addr)
        return result.value

    def readDword( self, addr ):
        result = c_uint(0)
        bytes_read = c_uint(0)
        read_result = ReadProcessMemory( self._process, addr, byref(result), 4, byref(bytes_read) )
        if 0 == read_result:
            raise ReadError(addr)
        return result.value

    def readWord( self, addr ):
        result = c_uint(0)
        bytes_read = c_uint(0)
        read_result = ReadProcessMemory( self._process, addr, byref(result), 2, byref(bytes_read) )
        if 0 == read_result:
            raise ReadError(addr)
        return result.value

    def readByte( self, addr ):
        result = c_uint(0)
        bytes_read = c_uint(0)
        read_result = ReadProcessMemory( self._process, addr, byref(result), 1, byref(bytes_read) )
        if 0 == read_result:
            raise ReadError(addr)
        return result.value

    def readMemory( self, addr, length ):
        result = ARRAY(c_char, length)('\x00')
        bytes_read = c_uint(0)
        read_result = ReadProcessMemory( self._process, addr, byref(result), sizeof(result), byref(bytes_read) )
        if 0 == read_result:
            raise ReadError(addr)
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
        if isinstance(data, (int, long)):
            data = struct.pack('<Q', data)
        data_to_write = c_buffer(data, 8)
        bytes_written = c_uint(0)
        WriteProcessMemory( self._process, addr, data_to_write, 8, byref(bytes_written) )

    def writeDword( self, addr, data ):
        if isinstance(data, (int, long)):
            data = struct.pack('<L', data)
        data_to_write = c_buffer(data, 4)
        bytes_written = c_uint(0)
        WriteProcessMemory( self._process, addr, data_to_write, 4, byref(bytes_written) )

    def writeWord( self, addr, data ):
        if isinstance(data, (int, long)):
            data = struct.pack('<H', data)
        data_to_write = c_buffer(data, 2)
        bytes_written = c_uint(0)
        WriteProcessMemory( self._process, addr, data_to_write, 2, byref(bytes_written) )

    def writeByte( self, addr, data ):
        if isinstance(data, (int, long)):
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

    def getAddressAttributes(self, addr):
        memBasicInfo = MEMORY_BASIC_INFORMATION()
        read_result = VirtualQueryEx(
                            self._process, 
                            addr, 
                            byref(memBasicInfo), 
                            sizeof(MEMORY_BASIC_INFORMATION))
        if 0 == read_result:
            raise Exception("Failed to query memory attributes for address 0x%x" % i)
        return (memBasicInfo.Protect)


    def isAddressWritable( self, addr ):
        return 0 != (self.getAddressAttributes(addr) & self.WRITE_ATTRIBUTES_MASK)

    def isAddressReadable( self, addr ):
        return 0 != (self.getAddressAttributes(addr) & self.READ_ATTRIBUTES_MASK)

    def isAddressExecuatable( self, addr ):
        return 0 != (self.getAddressAttributes(addr) & self.EXECUTE_ATTRIBUTES_MASK)

    def isAddressValid( self, addr ):
        result = c_uint(0)
        bytes_read = c_uint(0)
        returncode = ReadProcessMemory( self._process, addr, byref(result), 1, byref(bytes_read) )
        if 0 != returncode and 1 == bytes_read.value:
            return True
        return False

    def getMemoryMapByQuery( self ):
        """ Get map of all the memory with names of the modules the memory belongs to """

        if self._is_win64:
            raise Excpetion("Not supported on x64")
        try:
            import pefile
        except ImportError:
            raise Exception("You must install the pefile module to use this function")
        if None == EnumProcessModulesEx:
            raise Exception("This function is not supported on this build of Windows")
        
        result = {}

        # Get all modules names, and on the way the size of the binary of each module
        modules = ARRAY( c_void_p, self.PAGE_SIZE )(0)
        bytes_written = c_uint(0)
        EnumProcessModulesEx( self._process, byref(modules), sizeof(modules), byref(bytes_written), win32con.LIST_MODULES_ALL )
        num_modules = bytes_written.value / sizeof(c_void_p(0))
        for module_iter in range(num_modules):
            module_name = ARRAY( c_char, 1000 )('\x00')
            GetModuleBaseName( self._process, modules[module_iter], byref(module_name), sizeof(module_name) )
            module_name = module_name.value
            module_cut_name = module_name.replace('\x00', '')
            module_info = MODULEINFO(0)
            GetModuleInformation( self._process, modules[module_iter], byref(module_info), sizeof(module_info) )
            module_base = module_info.lpBaseOfDll
            module_size = module_info.SizeOfImage
            if module_base & self.PAGE_SIZE_MASK != 0:
                raise Exception("Module not page aligned")
            result[module_base] = (
                            module_cut_name, 
                            module_size, 
                            self.getAddressAttributes(module_base))
            # Get the sections
            module_bin = self.readMemory(module_base, self.PAGE_SIZE) #module_info.SizeOfImage)
            parsed_pe = pefile.PE(data=module_bin, fast_load=True)
            for section in parsed_pe.sections:
                section_addr = (section.VirtualAddress & 0xfffff000) + module_base
                section_size = section.SizeOfRawData
                section_attributes = self.getAddressAttributes(section_addr)
                section_name = module_cut_name + '!' + section.Name.replace('\x00', '')
                # Algin to end of page
                if 0 == section_size:
                    section_size = self.PAGE_SIZE
                elif (section_size & self.PAGE_SIZE_MASK) != 0:
                    section_size += self.PAGE_SIZE - (section_size & self.PAGE_SIZE_MASK)
                # Append to list
                sectionInMap = False
                for addr, block in result.items():
                    if addr == section_addr:
                        result[addr] = (
                                section_name,
                                section_size, 
                                section_attributes )
                        result[addr + section_size] = (
                                block[0],
                                block[1] - section_size,
                                self.getAddressAttributes(addr + section_size))
                        sectionInMap = True
                        break
                    elif addr <= section_addr and (addr + block[1]) > section_addr:
                        firstPartSize   = section_addr - addr
                        lastPartSize    = block[1] - firstPartSize - section_size
                        result[addr] = (
                                block[0],
                                firstPartSize,
                                block[2] )
                        result[section_addr] = (
                                section_name,
                                section_size,
                                section_attributes )
                        if 0 < lastPartSize:
                            result[section_addr + section_size] = (
                                block[0],
                                lastPartSize,
                                self.getAddressAttributes(section_addr + section_size))
                        sectionInMap = True
                        break
                if False == sectionInMap:
                    result[section_addr] = (
                                module_cut_name + '!' + section.Name.replace('\x00', ''), 
                                section_size, 
                                self.getAddressAttributes(section_addr))
            
        # Get all other memory and attributes of pages
        memory_map = ARRAY( c_uint, 0x80000 )(0)
        QueryWorkingSet( self._process, byref(memory_map), sizeof(memory_map) )
        number_of_pages = memory_map[0]
        # Add all pages
        for page in memory_map[1:1+number_of_pages]:
            addr = page & (0xfffff000)
            # We have no intrest in kernel pages
            if addr > 0x80000000:
                continue
            # Check if page is already in the list
            isPageSet = False
            for blockAddr, blockInfo in result.items():
                if blockAddr <= addr and (blockAddr + blockInfo[1]) > addr:
                    isPageSet = True
                    break
            if isPageSet:
                continue
            result[addr] = (
                "_PAGE_", 
                self.PAGE_SIZE,
                self.getAddressAttributes(addr))

        # Coalesce blocks
        keys = list(result.keys())
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

        return MemoryMap(result, self)

    def getMemoryMapByEnum( self ):
        if self._is_win64:
            raise Exception( "Not supported on x64" )
        result = {}
        one_byte = c_uint(0)
        bytes_read = c_uint(0)
        currentBlockStart = 0
        currentBlockSize  = 0
        currentBlockAttributes = None
        for i in range( 0, 0x80000000, self.PAGE_SIZE ):
            read_result = ReadProcessMemory( self._process, i, byref(one_byte), 1, byref(bytes_read) )
            if 0 != read_result and 0 < currentBlockSize:
                result[currentBlockStart] = ("", currentBlockSize, currentBlockAttributes)
            currentBlockSize = 0
            currentBlockStart = i + self.PAGE_SIZE
            currentBlockAttributes = None
            continue

            memBasicInfo = MEMORY_BASIC_INFORMATION()
            read_result = VirualQueryEx(self._process, i, byref(memBasicInfo), 1)
            if 0 == read_result:
                raise Exception("Failed to query memory attributes for address 0x{0:x}".format(i))
            pageAttributes = memBasicInfo.Protect
            if None == currentBlockAttributes:
                currentBlockAttributes = memBasicInfo.Protect
                currentBlockSize += self.PAGE_SIZE
            elif currentBlockAttributes != pageAttributes:
                # This page has different attributes so we would put it in a new block
                result[currentBlockStart] = ("", currentBlockSize, currentBlockAttributes)
                currentBlockSize = self.PAGE_SIZE
                currentBlockStart = i
                currentBlockAttributes = pageAttributes
            else:
                # Block continues
                currentBlockSize += self.PAGE_SIZE
        return MemoryMap(result, self)

    def disasm(self, addr, length=0x100, decodeType=1):
        if IS_DISASSEMBLER_FOUND:
            for opcode in distorm3.Decode(
                    addr, 
                    self.readMemory(addr, length),
                    decodeType):
                print('{0:x} {1:24s} {2:s}'.format(opcode[0], opcode[3], opcode[2]))
        else:
            raise Exception("No disassembler module")

    def getPointerSize(self):
        return self._POINTER_SIZE

    def getDefaultDataSize(self):
        return self._DEFAULT_DATA_SIZE


