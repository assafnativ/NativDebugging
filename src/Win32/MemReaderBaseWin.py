#
#   MemoryReaderBaseWin.py
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

from ..MemReaderBase import *
from .Win32Structs import *
from .Win32Utile import *
import exceptions

class MemReaderBaseWin( MemReaderBase ):
    def getEndianity(self):
        return '<' # Intel is always Little-endian

    def enumModules( self, isVerbose=False ):
        """
        Return list of tuples containg infromation about the modules loaded in memory in the form of
        (Address, module_name, module_size)
        """
        modules = ARRAY( c_void_p, 10000 )(0)
        bytes_written = c_uint(0)
        EnumProcessModules( self._process, byref(modules), sizeof(modules), byref(bytes_written) )
        num_modules = bytes_written.value / sizeof(c_void_p(0))
        for module_iter in range(num_modules):
            module_name = ARRAY( c_char, 10000 )('\x00')
            GetModuleBaseName( self._process, modules[module_iter], byref(module_name), sizeof(module_name) )
            module_name = module_name.raw.replace('\x00', '')
            module_info = MODULEINFO(0)
            GetModuleInformation( self._process, modules[module_iter], byref(module_info), sizeof(module_info) )
            module_base = module_info.lpBaseOfDll
            module_size = module_info.SizeOfImage
            if isVerbose:
                print("Module: (0x{0:x}) {1:s} of size (0x{2:x})".format(module_base, module_name, module_size))
            yield (module_base, module_name, module_size)

    def findModule( self, target_module, isVerbose=False ):
        target_module = target_module.lower()
        for base, name, moduleSize in self.enumModules(isVerbose):
            if target_module in name.lower():
                return base
        raise Exception("Can't find module")

    def getModulePath( self, base ):
        if isinstance(base, str):
            base = self.findModule(base)
        file_name = ARRAY(c_char, 10000)('\x00')
        file_name_size = c_uint(0)
        GetModuleFileName(base, byref(file_name), byref(file_name_size))
        return file_name.raw.replace('\x00\x00', '').decode('utf16')

    def _getSomePEInfo( self, module_base ):
        pe = module_base + self.readDword( module_base + win32con.PE_POINTER_OFFSET )
        first_section = self.readWord( pe + win32con.PE_SIZEOF_OF_OPTIONAL_HEADER_OFFSET) + win32con.PE_SIZEOF_NT_HEADER
        num_sections = self.readWord( pe + win32con.PE_NUM_OF_SECTIONS_OFFSET )
        isPePlus = (0x20b == self.readWord(pe + win32con.PE_OPTIONAL_HEADER_TYPE) )

        return (pe, first_section, num_sections, isPePlus)

    def getAllSections( self, module_base, isVerbose=False ):
        pe, first_section, num_sections, isPePlus = self._getSomePEInfo( module_base )
        bytes_read = c_uint(0)
        result = []
        for sections_iter in range(num_sections):
            if isVerbose:
                print(hex(pe + first_section + (sections_iter * win32con.IMAGE_SIZEOF_SECTION_HEADER)))
            section_name = self.readMemory( \
                    pe + first_section + (sections_iter * win32con.IMAGE_SIZEOF_SECTION_HEADER), \
                    win32con.PE_SECTION_NAME_SIZE )
            section_name = section_name.replace('\x00', '')
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
        if isinstance(target, (int, long)):
            isOrdinals = True
        else:
            isOrdinals = False
        for proc, procAddr in self._enumRemoteModuleProcs(base, rva, isOrdinals):
            if proc == target:
                return procAddr

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
                procName = self.readString(procNameAddr)
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
        for i in range(handleInfo.uCount):
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
                    print('Failed to duplicate handle %x' % systemHandles[i].Handle)
                    continue
                objectHandle = objectHandle.value
            except exceptions.WindowsError as e:
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
                print('Failed to query besic infromation for handle {0:x}'.format(systemHandles[i].Handle))

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
                    print('Failed to query object type')

                print(objectType.typeInfo.TypeName.Buffer)

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
                    print('Failed to query object name')

                name = objectName.nameInfo.UnicodeStr.Buffer
                print(name)

            if needToClose:
                CloseHandle(objectHandle)
                
