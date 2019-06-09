#
#   InjectDll.py
#
#   InjectDll - Dll injection module for python
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

# Imports
from abc import ABCMeta, abstractmethod
from .Win32Structs import *
from .MemReaderBaseWin import *
from ..Utilities import integer_types
from struct import pack
from builtins import range
import sys

class InjectDll( object ):
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        """ Pure virtual """
        raise NotImplementedError("Pure function call")

    def injectDll(self, dllName, LoadLibraryA_address=None, creationFlags=0):
        return self.injectDllCreateRemoteThread(dllName, LoadLibraryA_address, creationFlags)

    def injectDllQueueUserAPC(self, dllName):
        # TODO
        pass

    def _injectDllByRemoteThreadOnLoadLibrary(self, dllName, LoadLibraryA_address=None, creationFlags=0):
        if None == LoadLibraryA_address:
            LoadLibraryA_address = self.findProcAddress(b"kernel32.dll", b"LoadLibraryA")
        self.injectThreadHandle = self.createRemoteThreadAtAddress(LoadLibraryA_address, param=dllName, creationFlags=creationFlags)
        ResumeThread(self.injectThreadHandle)

    #dt /r _IMAGE_NT_HEADERS64
    #ucrtbased!_IMAGE_NT_HEADERS64
    #   +0x000 Signature        : Uint4B
    #   +0x004 FileHeader       : _IMAGE_FILE_HEADER
    #      +0x000 Machine          : Uint2B
    #      +0x002 NumberOfSections : Uint2B
    #      +0x004 TimeDateStamp    : Uint4B
    #      +0x008 PointerToSymbolTable : Uint4B
    #      +0x00c NumberOfSymbols  : Uint4B
    #      +0x010 SizeOfOptionalHeader : Uint2B
    #      +0x012 Characteristics  : Uint2B
    #   +0x018 OptionalHeader   : _IMAGE_OPTIONAL_HEADER64
    #      +0x000 Magic            : Uint2B
    #      +0x002 MajorLinkerVersion : UChar
    #      +0x003 MinorLinkerVersion : UChar
    #      +0x004 SizeOfCode       : Uint4B
    #      +0x008 SizeOfInitializedData : Uint4B
    #      +0x00c SizeOfUninitializedData : Uint4B
    #      +0x010 AddressOfEntryPoint : Uint4B
    #      +0x014 BaseOfCode       : Uint4B
    #      +0x018 ImageBase        : Uint8B
    #      +0x020 SectionAlignment : Uint4B
    #      +0x024 FileAlignment    : Uint4B
    #      +0x028 MajorOperatingSystemVersion : Uint2B
    #      +0x02a MinorOperatingSystemVersion : Uint2B
    #      +0x02c MajorImageVersion : Uint2B
    #      +0x02e MinorImageVersion : Uint2B
    #      +0x030 MajorSubsystemVersion : Uint2B
    #      +0x032 MinorSubsystemVersion : Uint2B
    #      +0x034 Win32VersionValue : Uint4B
    #      +0x038 SizeOfImage      : Uint4B
    #      +0x03c SizeOfHeaders    : Uint4B
    #      +0x040 CheckSum         : Uint4B
    #      +0x044 Subsystem        : Uint2B
    #      +0x046 DllCharacteristics : Uint2B
    #      +0x048 SizeOfStackReserve : Uint8B
    #      +0x050 SizeOfStackCommit : Uint8B
    #      +0x058 SizeOfHeapReserve : Uint8B
    #      +0x060 SizeOfHeapCommit : Uint8B
    #      +0x068 LoaderFlags      : Uint4B
    #      +0x06c NumberOfRvaAndSizes : Uint4B
    #      +0x070 DataDirectory    : [16] _IMAGE_DATA_DIRECTORY
    #         +0x000 VirtualAddress   : Uint4B
    #         +0x004 Size             : Uint4B
    def _injectDllPathImportsTable(self, dllName):
        # Process has not started yet, try to inject by modifying imports list
        # Based on https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format
        for module_base in self.enumModulesAddresses():
            lfanew = self.readDword(module_base + 0x3c)
            nt_header_addr = module_base + lfanew
            machine = self.readWord(nt_header_addr + 0x4)
            if 0 == machine:
                continue
            optional_header_size = self.readWord(nt_header_addr + 0x14)
            characteristics = self.readWord(nt_header_addr + 0x16)
            if characteristics & win32con.IMAGE_FILE_DLL:
                continue

            # This is most likely the main module
            break
        else:
            raise Exception("Main module not found!")

        # Pad dll name
        dllName = padBuffer(dllName, 0x10)

        magic = self.readWord(nt_header_addr + 0x18)
        if magic == win32con.IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            is32Bit = True
        elif magic == win32con.IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            is32Bit = False
        else:
            raise Exception("Unknown image magic: 0x%x" % magic)

        # Check for CLR (Common Language Runtime)
        number_of_sections = self.readWord(nt_header_addr + 0x6)
        if is32Bit:
            directory_addr = nt_header_addr + 0x7c
        else:
            directory_addr = nt_header_addr + 0x88

        iat_dir_offset = self.readDword(directory_addr + (12 * 8))
        iat_dir_size   = self.readDword(directory_addr + (12 * 8) + 4)
        iat_dir_addr   = module_base + iat_dir_offset
        import_dir_offset = self.readDword(directory_addr + 8)
        import_dir_size   = self.readDword(directory_addr + 8 + 4)

        # Nullify the checksum, not sure why
        self.deprotectAndWriteDword(nt_header_addr + 0x58, 0)

        # Zero out the bound table so loader doesn't use it instead of our new table.
        self.deprotectAndWriteDword(directory_addr + (11 * 8), 0)
        self.deprotectAndWriteDword(directory_addr + (11 * 8) + 4, 0)

        # If the file didn't have an IAT_DIRECTORY we create a new one
        for section_index in range(number_of_sections):
            if 0 != iat_dir_addr:
                break
            section_offset = self.readDword((section_index * 0x28) + 0xc)
            section_size   = self.readDword((section_index * 0x28) + 0x8)
            section_end = section_offset + section_size
            if (section_offset <= import_dir_offset) and (import_dir_offset < section_end):
                self.deprotectAndWriteDword(directory_addr + (12 * 8), section_offset)
                self.deprotectAndWriteDword(directory_addr + (12 * 8) + 4, section_size)

        sizeof_IMAGE_IMPORT_DESCRIPTOR = 0x14
        number_of_imports = import_dir_size // sizeof_IMAGE_IMPORT_DESCRIPTOR
        old_import_dir = self.readMemory(
                module_base + import_dir_offset,
                number_of_imports * sizeof_IMAGE_IMPORT_DESCRIPTOR)
        if (b'\x00' * sizeof_IMAGE_IMPORT_DESCRIPTOR) == old_import_dir[-sizeof_IMAGE_IMPORT_DESCRIPTOR:]:
            old_import_dir = old_import_dir[:-sizeof_IMAGE_IMPORT_DESCRIPTOR]
        self.dd(module_base + import_dir_offset, 0x200)
        # Add one more for the new DLL
        number_of_imports += 1
        # Caculate the required space for the new IAT
        required_space = number_of_imports * sizeof_IMAGE_IMPORT_DESCRIPTOR
        # Pad to 8 bytes
        imports_table_size = required_space
        required_space -= required_space % -0x10
        # Add the required space for Import Lookup Table RVA
        if is32Bit:
            required_space += 8 * 2
        else:
            required_space += 0x10 * 2
        # Add the required space for dll name
        required_space += len(dllName)
        # Room for some padding
        required_space += 0x10

        # Allocate remote buffer
        free_memory_address = self.findFreeMemoryNearBase(module_base, required_space)
        allocated_address = self.allocateRemoteAtAddress(free_memory_address, required_space)
        print(hex(module_base))
        assert(free_memory_address == allocated_address)

        # Generate the patch
        path_buffer_offset = free_memory_address - module_base
        dll_name_offset = path_buffer_offset
        patch_buffer = dllName
        import_lookup_table_offset = path_buffer_offset + len(patch_buffer)
        if is32Bit:
            patch_buffer += pack(b'LL', 0x80000001, 0)
        else:
            patch_buffer += pack(b'QQ', 0x8000000000000001, 0)
        patch_buffer = padBuffer(patch_buffer)
        import_address_table_offset = path_buffer_offset + len(patch_buffer)
        if is32Bit:
            patch_buffer += pack(b'LL', 0x80000001, 0)
        else:
            patch_buffer += pack(b'QQ', 0x8000000000000001, 0)
        patch_buffer = padBuffer(patch_buffer)
        new_import_dir_offset = path_buffer_offset + len(patch_buffer)
        patch_buffer += old_import_dir
        patch_buffer += pack(b'LLLLL', import_lookup_table_offset, 0, 0, dll_name_offset, import_address_table_offset)
        patch_buffer += b'\x00' * sizeof_IMAGE_IMPORT_DESCRIPTOR

        # Write the patch to the remote process
        self.deprotectAndWriteMemory(free_memory_address, patch_buffer)

        # Write offset to the new import dir
        self.deprotectAndWriteDword(directory_addr + 8, new_import_dir_offset)
        self.deprotectAndWriteDword(directory_addr + 8 + 4, imports_table_size)
        printAsDwordsTable(patch_buffer)

    def _sanitizeDllName(self, dllName):
        if dllName[-1] != b'\x00':
            dllName += b"\x00"
        return dllName

    def injectDllCreateRemoteThread(self, dllName, LoadLibraryA_address=None, creationFlags=0):
        dllName = self._sanitizeDllName(dllName)
        self._injectDllByRemoteThreadOnLoadLibrary(dllName, LoadLibraryA_address, creationFlags)

    def injectDllPatchImportsTable(self, dllName):
        dllName = self._sanitizeDllName(dllName)
        self._injectDllPathImportsTable(dllName)

    def createRemoteThreadAtAddress(self, remoteAddress, param=None, creationFlags=0):
        if isinstance(param, (str, bytes)):
            param = self._allocateAndWrite( param )
        elif isinstance(param, integer_types):
            pass
        elif None==param:
            param = 0
        else:
            raise Exception("Unsupported param")

        remote_thread_id = c_uint32(0)
        remote_thread = CreateRemoteThread( \
                            self._process,
                            None,
                            0,
                            remoteAddress,
                            param,
                            creationFlags,
                            byref(remote_thread_id) )
        return remote_thread, remote_thread_id.value

    def _allocateAndWrite(self, data):
        remoteAddress = self.allocateRemote(len(data))
        self.writeMemory(remoteAddress, data)
        return remoteAddress

    def allocateRemote(self, length):
        return self.allocateRemoteAtAddress(None, length)

    def allocateRemoteAtAddress(self, addr, length):
        remoteAddress = \
                VirtualAllocEx( self._process,
                                c_void_p(addr),
                                length,
                                win32con.MEM_RESERVE | win32con.MEM_COMMIT,
                                win32con.PAGE_READWRITE )
        if not remoteAddress:
            print("Attempt to allocate at %x (%x) failed %x" % (addr, length, self._process))
            x = input()
            raise WinError()
        return remoteAddress


    def findFreeMemoryNearBase(self, base_address, length):
        # Set length to the minimum allocation granularity MM_ALLOCATION_GRANULARITY
        length = min(length, 0x10000)
        mem_basic_info = MEMORY_BASIC_INFORMATION()
        mem_basic_info.RegionSize = 0x1000
        mem_basic_info.BaseAddress = base_address - (base_address % -0x1000)
        while True:
            addr = mem_basic_info.BaseAddress + mem_basic_info.RegionSize
            addr -= addr % -0x1000
            query_result = VirtualQueryEx(
                                self._process,
                                c_void_p(addr),
                                byref(mem_basic_info),
                                sizeof(MEMORY_BASIC_INFORMATION))

            if 0 == int(query_result):
                raise Exception("Failed to query memory at 0x%x" % addr)
            if mem_basic_info.RegionSize & 0xfff:
                raise Exception("Couldn't find free memory near base")
            if mem_basic_info.State != win32con.MEM_FREE:
                continue
            if mem_basic_info.BaseAddress <= base_address:
                continue

            if length <= mem_basic_info.RegionSize:
                break

        addr = mem_basic_info.BaseAddress
        # MM_ALLOCATION_GRANULARITY ?
        addr -= addr % -0x10000

        return addr


    def injectRPyC(self, pythonDll=None):
        if None == pythonDll:
            pythonDll = 'python%d%d.dll' % (sys.version_info.major, sys.version_info.minor)
        pythonAddr = injectDll(pythonDll)


