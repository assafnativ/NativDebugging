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

class MemReaderBaseWin( MemReaderBase ):
    def getEndianity(self):
        return '<' # Intel is always Little-endian

    def enumModules( self, isVerbos=False ):
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
            if isVerbos:
                print("Module: (0x{0:x}) {1:s} of size (0x{2:x})".format(module_base, module_name, module_size))
            yield (module_base, module_name, module_size)

    def findModule( self, target_module, isVerbos=False ):
        target_module = target_module.lower()
        for base, name, moduleSize in self.enumModules(isVerbos):
            if target_module in name.lower():
                return base
        raise Exception("Can't find module")

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
        for sections_iter in range(num_sections):
            if isVerbos:
                print(hex(pe_offset + first_section + (sections_iter * IMAGE_SIZEOF_SECTION_HEADER)))
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
                print("Section: {0:s} @0x{1:x} of 0x{2:x} bytes".format(section_name, section_base, section_size))
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
            except WindowsError as e:
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
                
