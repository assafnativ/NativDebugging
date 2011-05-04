#
#   ProcessInspector.py
#
#   ProcessInspector - Remote process memory inspection python module
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

from ..Interfaces import MemReaderInterface, MemWriterInterface, GUIDisplayInterface

from .Win32Structs import *
import sys
import struct
from pefile import *

PAGE_SIZE = 0x1000

from ..Utile import *
try:
    from ..QtWidgets import *
    IS_GUI_FOUND = True
except ImportError, e:
    #print("No GUI support")
    IS_GUI_FOUND = False

def attach(targetProcessId):
    return ProcessInspector(targetProcessId)

class ProcessInspector( MemReaderInterface, MemWriterInterface, GUIDisplayInterface ):
    def __init__( self, target_process_id ):
        adjustDebugPrivileges()
        self._processId = target_process_id
        self._openProcess( target_process_id )
        temp_void_p = c_void_p(1)
        temp_void_p.value -= 2
        self._is_win64 = (temp_void_p.value > (2**32))
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
        read_result = ReadProcessMemory( self._process, addr, byref(result), sizeof(result), byref(bytes_read) )
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

    def readString( self, addr, isUnicode = False ):
        result = ''
        bytes_read = c_uint(0)
        char = c_uint(0)
        while True:
            if False == isUnicode:
                try:
                    ReadProcessMemory( self._process, addr, byref(char), 1, byref(bytes_read) )
                except WindowsError:
                    return result
                addr += 1
            else:
                try:
                    ReadProcessMemory( self._process, addr, byref(char), 2, byref(bytes_read) )
                except WindowsError:
                    return result
                addr += 2
            if 1 < char.value and char.value < 0x80:
                result += chr(char.value)
            else:
                return result

    def writeAddr( self, addr, data ):
        raise Excpetion('Unsupported yet')
        if type(0) == type(data) or type(0l) == type(data):
            data = struct.pack('<l', data)
        data_to_write = c_buffer(data, sizeof(c_void_p))
        bytes_written = c_uint(0)
        WriteProcessMemory( self._process, addr, data_to_write, sizeof(data_to_write), byref(bytes_written) )

    def writeQword( self, addr, data ):
        if type(0) == type(data) or type(0l) == type(data):
            data = struct.pack('<Q', data)
        data_to_write = c_buffer(data, 8)
        bytes_written = c_uint(0)
        WriteProcessMemory( self._process, addr, data_to_write, 8, byref(bytes_written) )

    def writeDword( self, addr, data ):
        if type(0) == type(data) or type(0l) == type(data):
            data = struct.pack('<L', data)
        data_to_write = c_buffer(data, 4)
        bytes_written = c_uint(0)
        WriteProcessMemory( self._process, addr, data_to_write, 4, byref(bytes_written) )

    def writeWord( self, addr, data ):
        if type(0) == type(data) or type(0l) == type(data):
            data = struct.pack('<H', data)
        data_to_write = c_buffer(data, 2)
        bytes_written = c_uint(0)
        WriteProcessMemory( self._process, addr, data_to_write, 2, byref(bytes_written) )

    def writeByte( self, addr, data ):
        if type(0) == type(data) or type(0l) == type(data):
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
        if type('') == type(target):
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
        elif type(0) == type(target):
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

        if type(0) == type(target):
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

    def resolveOffsetsList( self, start, l, isVerbos = False ):
        result = [start]
        for i in l:
            result.append(self.readAddr(result[-1]+i))
        if True == isVerbos:
            if None != self.solveAddr:
                outputString = '['
                for i in xrange(len(result)):
                    addr = result[i]
                    addrName = self.solveAddr(addr)
                    if None != addrName:
                        outputString += addrName
                    else:
                        outputString += hex(addr)
                    if i != (len(result) - 1):
                        outputString += ', '
                outputString += ']'
                print outputString
            else:
                print map(hex, result)
        return result

    def printRecursiveFindResult( self, result ):
        outputString = hex(result[0]) + ' '
        outputString += str(map(hex, result[1])) + ' '
        outputString += str(result[2])
        print outputString

    def recursiveFind( self, target, start_address, length, hops = 1, delta = 0, must = None, isVerbos = False):
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

    def _recursiveFindInt( self, target, start_address, length, hops = 1, delta = 0, path = [], isVerbos = False):
        try:
            data = self.readMemory(start_address, length)
        except WindowsError:
            return
        table_data = makeAddrList(data)
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
        except WindowsError:
            return
        table_data = makeAddrList(data)
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
        except WindowsError:
            return
        table_data = makeAddrList(data)
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
        except WindowsError:
            return
        table_data = makeAddrList(data)
        if type('') == type(target):
            try:
                addr = self.resolveOffsetsList(start_address, must_jumps[:-1])[-1]
                data = self.readMemory(addr + must_jumps[-1], len(target) * 2)
            except WindowsError:
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
                except WindowsError:
                    pass
            if hops > 0 and self.isAddressValid(table_data[i]):
                for x in self._recursiveFindWithMust( target, table_data[i], must_jumps, length, hops - 1, delta, path + [i * 4] ):
                    yield x

    def findModule( self, target_module, isVerbos=False ):
        modules = ARRAY( c_void_p, 10000 )(0)
        module_name = ARRAY( c_char, 10000 )('\x00')
        bytes_written = c_uint(0)
        EnumProcessModules( self._process, byref(modules), sizeof(modules), byref(bytes_written) )
        num_modules = bytes_written.value / sizeof(c_void_p(0))
        if isVerbos:
            print 'Modules:'
        is_module_found = False
        for module_iter in xrange(num_modules):
            GetModuleBaseName( self._process, modules[module_iter], byref(module_name), sizeof(module_name) )
            if isVerbos:
                print 'Module:', module_name.raw.replace('\x00', '')
            if target_module.lower() in module_name.raw.replace('\x00' ,'').lower():
                is_module_found = True
                break

        if False == is_module_found:
            raise Exception("Can't find module")

        module_info = MODULEINFO(0)
        GetModuleInformation( self._process, modules[module_iter], byref(module_info), sizeof(module_info) )
        module_base = module_info.lpBaseOfDll

        return module_base


    def getAllSections( self, module_base, isVerbos=False ):
        PE_POINTER_OFFSET                   = 0x3c
        PE_SIZEOF_OF_OPTIONAL_HEADER_OFFSET = 0x14
        PE_SIZEOF_NT_HEADER                 = 0x18
        PE_NUM_OF_SECTIONS_OFFSET           = 0x06
        IMAGE_SIZEOF_SECTION_HEADER         = 40
        PE_SECTION_NAME_SIZE                = 0x08
        PE_SECTION_VOFFSET_OFFSET           = 0x0c
        PE_SECTION_SIZE_OF_RAW_DATA_OFFSET  = 0x10

        bytes_read = c_uint(0)
        pe_offset = module_base
        pe_offset += self.readDword( module_base + PE_POINTER_OFFSET )
        first_section = self.readWord( pe_offset + PE_SIZEOF_OF_OPTIONAL_HEADER_OFFSET) + PE_SIZEOF_NT_HEADER
        num_sections = self.readWord( pe_offset + PE_NUM_OF_SECTIONS_OFFSET )
        result = []
        for sections_iter in xrange(num_sections):
            if isVerbos:
                print hex(pe_offset + first_section + (sections_iter * IMAGE_SIZEOF_SECTION_HEADER))
            section_name = self.readMemory( \
                    pe_offset + first_section + (sections_iter * IMAGE_SIZEOF_SECTION_HEADER), \
                    PE_SECTION_NAME_SIZE )
            section_name = section_name.replace('\x00', '')
            section_base = self.readDword( \
                    pe_offset + first_section + (sections_iter * IMAGE_SIZEOF_SECTION_HEADER) + PE_SECTION_VOFFSET_OFFSET )
            section_size = self.readDword( \
                    pe_offset + first_section + (sections_iter * IMAGE_SIZEOF_SECTION_HEADER) + PE_SECTION_SIZE_OF_RAW_DATA_OFFSET )
            result.append( (section_name, section_base, section_size) )
            if isVerbos:
                print "Section:", section_name, "@0x%x of 0x%x bytes" % (section_base, section_size)
        return result


    def findSection( self, module_base, target_section, isVerbos=False ):
        target_section = target_section.lower()
        for section in self.getAllSections( module_base, isVerbos ):
            if section[0].lower() == target_section:
                return section
        return ('',0,0)

    def getHandles( self ):
        handleInfo = SYSTEM_HANDLE_INFORMATION()
        bytesNeeded = c_uint(0)
        ntstatus = NtQuerySystemInformation(
                        win32con.SystemHandleInformation,
                        byref(handleInfo),
                        sizeof(handleInfo),
                        byref(bytesNeeded))
        if (win32con.STATUS_INFO_LENGTH_MISMATCH == ntstatus):
            class SYSTEM_HANDLE_INFORMATION_TAG( Structure ):
                _fields_ = [
                        ('uCount',      c_uint),
                        ('SystemHandle', SYSTEM_HANDLE * ((bytesNeeded.value - 4) / sizeof(SYSTEM_HANDLE))) ]
            handleInfo = SYSTEM_HANDLE_INFORMATION_TAG()
            ntstatus = NtQuerySystemInformation(
                        win32con.SystemHandleInformation,
                        byref(handleInfo),
                        sizeof(handleInfo),
                        byref(bytesNeeded))
            if (win32con.STATUS_SUCCESS != ntstatus):
                raise Exception('Querying system infromation failed')
        if (win32con.STATUS_SUCCESS != ntstatus):
            raise Exception("Failed to query system information %x" % ntstatus)
        systemHandles = handleInfo.SystemHandle
        for i in xrange(handleInfo.uCount):
            if (self._processId != systemHandles[i].uIdProcess):
                continue
            objectHandle = c_int(0)
            try:
                needToClose = True
                DuplicateHandle(
                        self._process, 
                        systemHandles[i].Handle,
                        GetCurrentProcess(),
                        byref(objectHandle),
                        win32con.STANDARD_RIGHTS_REQUIRED,
                        False,
                        0 )
                if (not objectHandle.value):
                    print 'Failed to duplicate handle %x' % systemHandles[i].Handle
                    continue
                objectHandle = objectHandle.value
            except WindowsError, e:
                needToClose = False
                if 5 == e.winerror:
                    objectHandle = systemHandles[i].Handle

            objectBasicInfo = OBJECT_BASIC_INFORMATION()
            bytesNeeded = c_uint(0)
            ntstatus = NtQueryObject(
                            objectHandle,
                            win32con.ObjectBasicInformation,
                            byref(objectBasicInfo),
                            sizeof(objectBasicInfo),
                            byref(bytesNeeded) )
            if (win32con.STATUS_SUCCESS != ntstatus):
                print 'Failed to query besic infromation for handle %x' % systemHandles[i].Handle

            if objectBasicInfo.TypeInformationLength > 0:
                class OBJECT_TYPE_INFROMATION_TAG( Structure ):
                    _fields_ = [
                            ('typeInfo',    OBJECT_TYPE_INFROMATION),
                            ('data',        c_byte * (objectBasicInfo.TypeInformationLength - sizeof(OBJECT_TYPE_INFROMATION)))]
                objectType = OBJECT_TYPE_INFROMATION_TAG()
                ntstatus = NtQueryObject(
                                objectHandle,
                                win32con.ObjectTypeInformation,
                                byref(objectType),
                                sizeof(objectType),
                                byref(bytesNeeded))
                if (win32con.STATUS_SUCCESS != ntstatus):
                    print 'Failed to query object type'

                print objectType.typeInfo.TypeName.Buffer

            if objectBasicInfo.NameInformationLength > 0:
                class OBJECT_NAME_INFORMATION_TAG( Structure ):
                    _fields_ = [
                            ('nameInfo',    OBJECT_NAME_INFORMATION),
                            ('data',        c_byte * (objectBasicInfo.NameInformationLength - sizeof(OBJECT_NAME_INFORMATION)))]
                objectName = OBJECT_NAME_INFORMATION_TAG()
                ntstatus = NtQueryObject(
                                objectHandle,
                                win32con.ObjectNameInformation,
                                byref(objectName),
                                sizeof(objectName),
                                byref(bytesNeeded) )
                if (win32con.STATUS_SUCCESS != ntstatus):
                    print 'Failed to query object name'

                name = objectName.nameInfo.UnicodeStr.Buffer
                print name

            if needToClose:
                CloseHandle(objectHandle)
        
    def _hexDisplay(self, address, length=0x1000, showOffsets=False, size=4):
        if showOffsets:
            newWindow = HexView(self.readMemory(address, length), start_address=0, item_size=size)
        else:
            newWindow = HexView(self.readMemory(address, length), start_address=address, item_size=size)
        newWindow.show()
        return newWindow

    def _mapDisplay(self, address, length=0x1000, colorMap=None, itemsPerRow=MemoryMap.DEFAULT_LINE_SIZE):
        newWindow = MemoryMap(self.readMemory(address, length), colorMap, itemsPerRow)
        newWindow.show()
        return newWindow

    def _unsupported(self, *args, **kw):
        raise NotImplementedError("Unsupported function")

    def mapDisplay(self, *args, **kw):
        if IS_GUI_FOUND:
            self.mapDisplay = self._mapDisplay
        else:
            self.mapDisplay = self._unsupported
        self.mapDisplay(*args, **kw)

    def hexDisplay(self, *args, **kw):
        if IS_GUI_FOUND:
            self.hexDisplay = self._hexDisplay
        else:
            self.hexDisplay = self._unsupported
        self.hexDisplay(*args, **kw)

    readNPrintBin      = readNPrintBin
    readNPrintDwords   = readNPrintDwords
    readNPrintWords    = readNPrintWords
    readNPrintQwords   = readNPrintQwords
    solveAddr      = None
    findInSymbols  = None
    findSymbol     = None
