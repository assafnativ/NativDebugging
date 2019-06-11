#
#   MemoryReaderBaseWin.py
#
#   MemoryReader - Remote process memory inspection python module
#   https://github.com/assafnativ/NativDebugging.git
#   Nativ.Assaf@gmail.com
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

from builtins import bytes
from ..MemReaderBase import *
from .Win32Structs import *
from .Win32Utilities import *
from ..Utilities import printIfVerbose, integer_types
try:
    import distorm3
    IS_DISASSEMBLER_FOUND = True
except ImportError as e:
    IS_DISASSEMBLER_FOUND = False

class MemReaderBaseWin( MemReaderBase ):
    def __init__(self, *argv, **argm):
        MemReaderBase(self, *argv, **argm)

    def getEndianity(self):
        return '<' # Intel is always Little-endian

    def enumModulesAddresses(self):
        ALLOCATION_GRANULARITY = 0x1000
        mem_basic_info = MEMORY_BASIC_INFORMATION()
        addr = ALLOCATION_GRANULARITY
        while True:
            if 0x7ffffffffff < addr:
                break
            queryResult = VirtualQueryEx(self._process, c_void_p(addr), byref(mem_basic_info), sizeof(mem_basic_info))
            assert(queryResult == sizeof(mem_basic_info))
            if 0xfff == (mem_basic_info.RegionSize & 0xfff):
                # This is the last mem region in user space
                break
            if (mem_basic_info.BaseAddress + mem_basic_info.RegionSize) < addr:
                # Overflow in address, we are probably done
                break
            else:
                new_addr = mem_basic_info.BaseAddress + mem_basic_info.RegionSize
                assert(addr < new_addr)
                addr = new_addr
            if (
                    (mem_basic_info.State != win32con.MEM_COMMIT) or
                    (win32con.PAGE_NOACCESS == (mem_basic_info.Protect & 0xff)) or
                    (0 != (mem_basic_info.Protect & win32con.PAGE_GUARD)) ):
                # Not a module
                continue
            module_addr = mem_basic_info.BaseAddress
            if b'MZ' != self.readMemory(module_addr, 2):
                # Not an MZ, not a module
                continue
            lfanew = self.readDword(module_addr + 0x3c)
            if (mem_basic_info.RegionSize - 4) < lfanew:
                # Invalid MZ header
                continue
            nt_header_addr = module_addr + lfanew
            if b'PE\x00\x00' != self.readMemory(nt_header_addr, 4):
                # Invalid PE
                continue

            yield module_addr

    def getPEBAddress(self):
        processInfo = PROCESS_BASIC_INFORMATION()
        NtQueryInformationProcess(self._process, win32con.PROCESS_BASIC_INFORMATION, byref(processInfo), sizeof(processInfo), None)
        return processInfo.PebBaseAddress

    def imageBaseAddressFromPeb(self, peb):
        return self.readAddr(peb + (self.getPointerSize() * 2))

    def enumModules( self, isVerbose=False ):
        """
        Return list of tuples containg infromation about the modules loaded in memory in the form of
        (Address, module_name, module_size)
        """
        modules = c_ARRAY( c_void_p, 0x10000 )(0)
        bytes_written = c_uint32(0)
        res = EnumProcessModules( self._process, byref(modules), sizeof(modules), byref(bytes_written))
        if 0 == res and 0 == bytes_written.value:
            # If this function is called from a 32-bit application running on WOW64, it can only enumerate the modules
            # of a 32-bit process. If the process is a 64-bit process, this function fails and the last error code is
            # ERROR_PARTIAL_COPY (299).
            # Or process not started yet
            raise Exception("Not supported")
        num_modules = bytes_written.value // sizeof(c_void_p(0))
        printIfVerbose("Found %d modules" % num_modules, isVerbose)
        for module_iter in range(num_modules):
            module_name = c_ARRAY( c_char, 10000 )(b'\x00')
            GetModuleBaseName( self._process, modules[module_iter], byref(module_name), sizeof(module_name) )
            module_name = module_name.raw.replace(b'\x00', b'')
            module_info = MODULEINFO(0)
            GetModuleInformation( self._process, modules[module_iter], byref(module_info), sizeof(module_info) )
            module_base = module_info.lpBaseOfDll
            if module_base != module_info.lpBaseOfDll:
                printIfVerbose("This is strange, found inconsistency module address (0x{0:x} 0x{1:x})".format(module_base, module_info.lpBaseOfDll), isVerbose)
            module_size = module_info.SizeOfImage
            printIfVerbose("Module: (0x{0:x}) {1!s} of size (0x{2:x})".format(module_base, module_name, module_size), isVerbose)
            yield (module_base, module_name, module_size)

    def findModule( self, target_module, isVerbose=False ):
        target_module = target_module.lower()
        for base, name, moduleSize in self.enumModules(isVerbose):
            if target_module in name.lower():
                return base
        raise Exception("Can't find module {0!s}".format(target_module))

    def getModulePath( self, base ):
        if isinstance(base, str):
            base = self.findModule(base)
        file_name = c_ARRAY(c_char, 10000)(b'\x00')
        file_name_size = c_uint32(0)
        GetModuleFileName(base, byref(file_name), byref(file_name_size))
        return file_name.raw.replace(b'\x00\x00', b'').decode('utf16')

    def _getSomePEInfo( self, module_base ):
        pe = module_base + self.readDword( module_base + win32con.PE_POINTER_OFFSET )
        first_section = self.readWord( pe + win32con.PE_SIZEOF_OF_OPTIONAL_HEADER_OFFSET) + win32con.PE_SIZEOF_NT_HEADER
        num_sections = self.readWord( pe + win32con.PE_NUM_OF_SECTIONS_OFFSET )
        isPePlus = (0x20b == self.readWord(pe + win32con.PE_OPTIONAL_HEADER_TYPE) )

        return (pe, first_section, num_sections, isPePlus)

    def getAllSections( self, module_base, isVerbose=False ):
        pe, first_section, num_sections, isPePlus = self._getSomePEInfo( module_base )
        bytes_read = c_uint32(0)
        result = []
        for sections_iter in range(num_sections):
            if isVerbose:
                print(hex(pe + first_section + (sections_iter * win32con.IMAGE_SIZEOF_SECTION_HEADER)))
            section_name = self.readMemory( \
                    pe + first_section + (sections_iter * win32con.IMAGE_SIZEOF_SECTION_HEADER), \
                    win32con.PE_SECTION_NAME_SIZE )
            section_name = section_name.replace(b'\x00', b'')
            section_base = self.readDword( \
                    pe + first_section + (sections_iter * win32con.IMAGE_SIZEOF_SECTION_HEADER) + win32con.PE_SECTION_VOFFSET_OFFSET )
            section_size = self.readDword( \
                    pe + first_section + (sections_iter * win32con.IMAGE_SIZEOF_SECTION_HEADER) + win32con.PE_SECTION_SIZE_OF_RAW_DATA_OFFSET )
            result.append( (section_name, section_base, section_size) )
            if isVerbose:
                print("Section: {0:s} @0x{1:x} of 0x{2:x} bytes".format(section_name, section_base, section_size))
        return result

    def findSection( self, module_base, target_section, isVerbose=False ):
        target_section = target_section.lower()
        for section in self.getAllSections( module_base, isVerbose ):
            if section[0].lower() == target_section:
                return section
        return ('',0,0)

    def getProcAddress( self, dllName, procName ):
        """
        Gets an address to a proc in a dll.
        Note, that this function is not relocation aware,
        use findProcAddress to get the real address.
        """
        module_handle = GetModuleHandle( dllName )
        return( GetProcAddress( module_handle, procName ) )

    def findRVA(self, base):
        """
        Returns a pointer to the RVA section of a specific module
        of the remote process
        """
        pe, first_section, num_sections, isPePlus = self._getSomePEInfo( base )
        if isPePlus:
            extraBytes = win32con.PE_PLUS_EXTRA_BYTES
        else:
            extraBytes = 0
        return base + self.readDword(pe + win32con.PE_RVA_OFFSET + extraBytes)

    def findProcAddress(self, dllName, target):
        """
        Search for exported function in a remote process.
        """
        base = self.findModule(dllName, isVerbose=False)
        rva = self.findRVA(base)
        if isinstance(target, integer_types):
            isOrdinals = True
        else:
            isOrdinals = False
        for proc, procAddr in self._enumRemoteModuleProcs(base, rva, isOrdinals):
            if proc == target:
                return procAddr
        raise Exception("Function %s not found in %s" % (str(target), dllName))

    def _enumRemoteModuleProcs(self, base, rva, isOrdinals=False):
        numProcs    = self.readDword(rva + win32con.RVA_NUM_PROCS_OFFSET)
        procsTable  = base + self.readDword(rva + win32con.RVA_PROCS_ADDRESSES_OFFSET)
        ordinalsTable = base + self.readDword(rva + win32con.RVA_PROCS_ORDINALS_OFFSET)
        procIndex = None
        if isOrdinals:
            # By ordinal
            # I think there is a bug here, but no one realy uses ordinal load
            for i in range(numProcs):
                ordinal = self.readWord(ordinalsTable + (i*2))
                yield (ordinal, base + self.readDword(procsTable + (ordinal * 4)))
        else:
            # By name
            numNames    = self.readDword(rva + win32con.RVA_NUM_PROCS_NAMES_OFFSET)
            namesTable  = base + self.readDword(rva + win32con.RVA_PROCS_NAMES_OFFSET)
            for i in range(numNames):
                procNameAddr = base + self.readDword(namesTable + (i*4))
                procName = bytes(self.readString(procNameAddr), 'utf8')
                procIndex = self.readWord(ordinalsTable + (i*2))
                yield (procName, base + self.readDword(procsTable + (procIndex * 4)))

    def enumRemoteModuleProcs(self, dllName, isOrdinals=False):
        """
        Iterate on exported function in a remote process.
        """
        base = self.findModule(dllName, isVerbose=False)
        rva = self.findRVA(base)
        for proc in self._enumRemoteModuleProcs(base, rva, isOrdinals=isOrdinals):
            yield proc

    def getHandles( self ):
        handleInfo = SYSTEM_HANDLE_INFORMATION()
        bytesNeeded = c_uint32(0)
        ntstatus = NtQuerySystemInformation(
                        win32con.SystemHandleInformation,
                        byref(handleInfo),
                        sizeof(handleInfo),
                        byref(bytesNeeded))
        if (win32con.STATUS_INFO_LENGTH_MISMATCH == ntstatus):
            class SYSTEM_HANDLE_INFORMATION_TAG( Structure ):
                _fields_ = [
                        ('uCount',      c_uint32),
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
        for i in range(handleInfo.uCount):
            if (self._processId != systemHandles[i].uIdProcess):
                continue
            objectHandle = c_int32(0)
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
                    print('Failed to duplicate handle %x' % systemHandles[i].Handle)
                    continue
                objectHandle = objectHandle.value
            except WindowsError as e:
                needToClose = False
                if 5 == e.winerror:
                    objectHandle = systemHandles[i].Handle

            objectBasicInfo = OBJECT_BASIC_INFORMATION()
            bytesNeeded = c_uint32(0)
            ntstatus = NtQueryObject(
                            objectHandle,
                            win32con.ObjectBasicInformation,
                            byref(objectBasicInfo),
                            sizeof(objectBasicInfo),
                            byref(bytesNeeded) )
            if (win32con.STATUS_SUCCESS != ntstatus):
                print('Failed to query besic infromation for handle {0:x}'.format(systemHandles[i].Handle))

            if objectBasicInfo.TypeInformationLength > 0:
                class OBJECT_TYPE_INFROMATION_TAG( Structure ):
                    _fields_ = [
                            ('typeInfo',    OBJECT_TYPE_INFROMATION),
                            ('data',        c_uint8 * (objectBasicInfo.TypeInformationLength - sizeof(OBJECT_TYPE_INFROMATION)))]
                objectType = OBJECT_TYPE_INFROMATION_TAG()
                ntstatus = NtQueryObject(
                                objectHandle,
                                win32con.ObjectTypeInformation,
                                byref(objectType),
                                sizeof(objectType),
                                byref(bytesNeeded))
                if (win32con.STATUS_SUCCESS != ntstatus):
                    print('Failed to query object type')

                print(objectType.typeInfo.TypeName.Buffer)

            if objectBasicInfo.NameInformationLength > 0:
                class OBJECT_NAME_INFORMATION_TAG( Structure ):
                    _fields_ = [
                            ('nameInfo',    OBJECT_NAME_INFORMATION),
                            ('data',        c_uint8 * (objectBasicInfo.NameInformationLength - sizeof(OBJECT_NAME_INFORMATION)))]
                objectName = OBJECT_NAME_INFORMATION_TAG()
                ntstatus = NtQueryObject(
                                objectHandle,
                                win32con.ObjectNameInformation,
                                byref(objectName),
                                sizeof(objectName),
                                byref(bytesNeeded) )
                if (win32con.STATUS_SUCCESS != ntstatus):
                    print('Failed to query object name')

                name = objectName.nameInfo.UnicodeStr.Buffer
                print(name)

            if needToClose:
                CloseHandle(objectHandle)

    def isAddressWritable( self, addr ):
        return 0 != (self.getAddressAttributes(addr) & self.WRITE_ATTRIBUTES_MASK)

    def isAddressReadable( self, addr ):
        return 0 != (self.getAddressAttributes(addr) & self.READ_ATTRIBUTES_MASK)

    def isAddressExecuatable( self, addr ):
        return 0 != (self.getAddressAttributes(addr) & self.EXECUTE_ATTRIBUTES_MASK)

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


