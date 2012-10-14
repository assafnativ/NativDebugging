
from ..Patterns import *

# All information is stolen from winnt.h

VALID_MACHINE_TYPES = {
        0x014c  : "I386",
        0x0162  : "R3000",
        0x0166  : "R4000",
        0x0168  : "R10000",
        0x0169  : "WCEMIPSV2",
        0x0184  : "ALPHA",
        0x01a2  : "SH3",
        0x01a3  : "SH3DSP",
        0x01a4  : "SH3E",
        0x01a6  : "SH4",
        0x01a8  : "SH5",
        0x01c0  : "ARM",
        0x01c2  : "THUMB",
        0x01c4  : "ARMNT",
        0x01d3  : "AM33",
        0x01F0  : "POWERPC",
        0x01f1  : "POWERPCFP",
        0x0200  : "IA64",
        0x0266  : "MIPS16",
        0x0284  : "ALPHA64",
        0x0366  : "MIPSFPU",
        0x0466  : "MIPSFPU16",
        0x0520  : "TRICORE",
        0x0CEF  : "CEF",
        0x0EBC  : "EBC",
        0x8664  : "AMD64",
        0x9041  : "M32R",
        0xC0EE  : "CEE" }

VALID_SECTION_ALGINMENTS = {
        0x00100000:  "1BYTES",
        0x00200000:  "2BYTES",
        0x00300000:  "4BYTES",
        0x00400000:  "8BYTES",
        0x00500000:  "16BYTES",
        0x00600000:  "32BYTES",
        0x00700000:  "64BYTES" }

ImageFileHeader = [
        SHAPE("Machine",            0, WORD(VALID_MACHINE_TYPES.keys())),
        SHAPE("NumberOfSections",   0, WORD()),
        SHAPE("TimeDateStamp",      0, CTIME()),
        SHAPE("PointerToSymTable",  0, DWORD()),
        SHAPE("NumberOfSymbols",    0, DWORD()),
        SHAPE("OptionalHeaderSize", 0, WORD()),
        SHAPE("Characteristics",    0, WORD()) ]

ImageSectionHeader = [
        SHAPE("Name",           0, STRING(size=8)),
        SHAPE("VirtualSize",    0, DWORD()),
        SHAPE("VirtualAddress", 0, DWORD()),
        SHAPE("RawDataSize",  0, DWORD()),
        SHAPE("PointerToRawData", 0, DWORD()),
        SHAPE("PointerToRelocations", 0, DWORD()),
        SHAPE("PointerToLinenumbers", 0, DWORD()),
        SHAPE("NumberOfRelocations", 0, WORD()),
        SHAPE("NumberOfLinenumbers", 0, WORD()),
        SHAPE("Characteristics", 0, DWORD()) ]

ImageDataDirectory = [
        SHAPE("VirtualAddress",     0, DWORD()),
        SHAPE("Size",               0, DWORD()) ]

ImageExportDirectory = [
        SHAPE("Characteristics", 0, DWORD()),
        SHAPE("TimeDateStamp", 0, CTIME()),
        SHAPE("MajorVersion", 0, WORD()),
        SHAPE("MinorVersion", 0, WORD()),
        SHAPE("Name", 0, DWORD()),
        SHAPE("Base", 0, DWORD()),
        SHAPE("NumberOfFunctions", 0, DWORD()),
        SHAPE("NumberOfNames", 0, DWORD()),
        SHAPE("FunctionsAddress", 0, DWORD()),
        SHAPE("NamesAddress", 0, DWORD()),
        SHAPE("NameOrdinalsAddress", 0, DWORD())
        ]

ImageImportDescriptor = [
        SHAPE("Characteristics", 0, DWORD()),
        SHAPE("TimeDateStamp", 0, CTIME()),
        SHAPE("ForwarderChain", 0, DWORD()),
        SHAPE("Name", 0, DWORD()),
        SHAPE("FirstThunk", 0, DWORD())
        ]

ImageOptionalHeader = [
        SHAPE("Magic",              0,  STRING(fixedValue='\x0b\x01')),
        SHAPE("MajorLinkerVersion", 0,  BYTE()),
        SHAPE("MinorLinkerVersion", 0,  BYTE()),
        SHAPE("CodeSize",         0,  DWORD()),
        SHAPE("InitializedDataSize", 0, DWORD()),
        SHAPE("UninitializedDataSize", 0, DWORD()),
        SHAPE("EntryPointAddress", 0, DWORD()),
        SHAPE("BaseOfCode",         0, DWORD()),
        SHAPE("BaseOfData",         0, DWORD()),
        SHAPE("ImageBase",          0, DWORD()),
        SHAPE("SectionAlignment",   0, DWORD()), #VALID_SECTION_ALGINMENTS.keys())),
        SHAPE("FileAlignment",      0, DWORD()),
        SHAPE("MajorOSVersion", 0, WORD()),
        SHAPE("MinorOSVersion", 0, WORD()),
        SHAPE("MajorImageVer",  0, WORD()),
        SHAPE("MinorImageVer",  0, WORD()),
        SHAPE("MajorSubsystemVer", 0, WORD()),
        SHAPE("MinorSubsystemVer", 0, WORD()),
        SHAPE("Win32VersionValue",  0, DWORD()),
        SHAPE("ImageSize",        0, DWORD()),
        SHAPE("HeadersSize",      0, DWORD()),
        SHAPE("CheckSum",           0, DWORD()),
        SHAPE("Subsystem",          0, WORD()),
        SHAPE("DllCharacteristics", 0, WORD()),
        SHAPE("StackReserveSize", 0, DWORD()),
        SHAPE("StackCommitSize",  0, DWORD()),
        SHAPE("HeapReserveSize",  0, DWORD()),
        SHAPE("HeapCommitSize",   0, DWORD()),
        SHAPE("LoaderFlags",        0, DWORD()),
        SHAPE("NumOfRvaAndSizes", 0, DWORD()),
        SHAPE("ExportDir",      0, STRUCT(ImageDataDirectory)),
        SHAPE("ImportDir",      0, STRUCT(ImageDataDirectory)),
        SHAPE("ResDir",         0, STRUCT(ImageDataDirectory)),
        SHAPE("ExceptionDir",   0, STRUCT(ImageDataDirectory)),
        SHAPE("SecurityDir",    0, STRUCT(ImageDataDirectory)),
        SHAPE("BaserelocDir",   0, STRUCT(ImageDataDirectory)),
        SHAPE("DebugDir",       0, STRUCT(ImageDataDirectory)),
        SHAPE("ArchDir",        0, STRUCT(ImageDataDirectory)),
        SHAPE("GlobalsDir",     0, STRUCT(ImageDataDirectory)),
        SHAPE("TLSDir",         0, STRUCT(ImageDataDirectory)),
        SHAPE("LoadConfDir",    0, STRUCT(ImageDataDirectory)),
        SHAPE("BoundImportDir", 0, STRUCT(ImageDataDirectory)),
        SHAPE("IATDir",         0, STRUCT(ImageDataDirectory)),
        SHAPE("DelayImportDir", 0, STRUCT(ImageDataDirectory)),
        SHAPE("ComDescriptorDir", 0, STRUCT(ImageDataDirectory)),
        SHAPE("ReservedDir",    0, STRUCT(ImageDataDirectory)),
        SHAPE("Exports", lambda ctx, addr: (ctx._perent._perent.AddressOfe_magic + ctx.ExportDir.VirtualAddress, ctx.ExportDir.VirtualAddress), STRUCT(ImageExportDirectory)),
        SHAPE("Imports", lambda ctx, addr: (ctx._perent._perent.AddressOfe_magic + ctx.ImportDir.VirtualAddress, ctx.ImportDir.VirtualAddress), STRUCT(ImageImportDescriptor))
        ]

ImageNtHeaders = [
        SHAPE("Signature", 0, STRING(fixedValue='PE\x00\x00')),
        SHAPE("FileHeader", 0, STRUCT(ImageFileHeader)),
        SHAPE("OptionalHeader", 0, STRUCT(ImageOptionalHeader)) ]

ImageDosHeader = [
        SHAPE("e_magic", 0, STRING(fixedValue="MZ")),
        SHAPE("e_cblp", 0, WORD()),
        SHAPE("e_cp", 0, WORD()),
        SHAPE("e_crlc", 0, WORD()),
        SHAPE("e_cparhdr", 0, WORD()),
        SHAPE("e_minalloc", 0, WORD()),
        SHAPE("e_maxalloc", 0, WORD()),
        SHAPE("e_ss", 0, WORD()),
        SHAPE("e_sp", 0, WORD()),
        SHAPE("e_csum", 0, WORD()),
        SHAPE("e_ip", 0, WORD()),
        SHAPE("e_cs", 0, WORD()),
        SHAPE("e_lfarlc", 0, WORD()),
        SHAPE("e_ovno", 0, WORD()),
        SHAPE("e_res", 0, ARRAY(4, WORD, ())),
        SHAPE("e_oemid", 0, WORD()),
        SHAPE("e_oeminfo", 0, WORD()),
        SHAPE("e_res2", 0, ARRAY(10, WORD, ())),
        SHAPE("e_lfanew", 0, DWORD()),
        SHAPE("PE", lambda ctx, addr: (addr + ctx.e_lfanew, ctx.e_lfanew), STRUCT(ImageNtHeaders))
        ]

#def getImports(baseCtx):
#    IMPORT_DESCRIPTOR_SIZE = 5 * 4
#    importsPat = []
#    importsAddr = baseCtx.PE.OptionalHeader.AddressOfImports
#    importsSize = baseCtx.PE.OptionalHeader.ImportDir.Size
#    numDescriptors = importsSize / IMPORT_DESCRIPTOR_SIZE
#    for i in range(numDescriptors):
#        importsPat.append(
#                SHAPE("Import%06x" % i, 0, STRUCT(ImageImportDescriptor)))


