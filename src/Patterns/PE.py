
from .Finder import *

# Resources:
#   winnt.h
#   corkami.com
#   Wikipedia
#   Microsoft docs http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/pecoff_v8.docx
#   http://www.csn.ul.ie/~caolan/publink/winresdump/winresdump/doc/pefile.html

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

PE32_MAGIC  = 0x010b
PE32P_MAGIC = 0x020b
VALID_PE_FORMATS = {
        PE32_MAGIC:  "PE32",
        PE32P_MAGIC: "PE32P",
        0x0107: "ROM" }

WINDOWS_SUBSYSTEMS = {
     0 : "IMAGE_SUBSYSTEM_UNKNOWN",
     1 : "IMAGE_SUBSYSTEM_NATIVE",
     2 : "IMAGE_SUBSYSTEM_WINDOWS_GUI",
     3 : "IMAGE_SUBSYSTEM_WINDOWS_CUI",
     7 : "IMAGE_SUBSYSTEM_POSIX_CUI",
     9 : "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    10 : "IMAGE_SUBSYSTEM_EFI_APPLICATION",
    11 : "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
    12 : "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
    13 : "IMAGE_SUBSYSTEM_EFI_ROM",
    14 : "IMAGE_SUBSYSTEM_XBOX" }

DLL_CHARACTERISTICS_FALGS = {
    0x0020  : "HIGH_ENTROPY_VA",
    0x0040  : "DYNAMIC_BASE",
    0x0080  : "FORCE_INTEGRITY",
    0x0100  : "NX_COMPAT",
    0x0200  : "NO_ISOLATION",
    0x0400  : "NO_SEH",
    0x0800  : "NO_BIND",
    0x1000  : "APPCONTAINER",
    0x2000  : "WDM_DRIVER",
    0x4000  : "GUARD_CF",
    0x8000  : "TERMINAL_SERVER_AWARE" }

ImageFileHeader = [
        SHAPE("Machine",            0, c_uint16(list(VALID_MACHINE_TYPES.keys()))),
        SHAPE("NumberOfSections",   0, c_uint16()),
        SHAPE("TimeDateStamp",      0, n_ctime()),
        SHAPE("PointerToSymTable",  0, c_uint32()),
        SHAPE("NumberOfSymbols",    0, c_uint32()),
        SHAPE("OptionalHeaderSize", 0, c_uint16()),
        SHAPE("Characteristics",    0, c_uint16()) ]

ImageSectionHeader = [
        SHAPE("Name",           0, n_buffer(size=8)),
        SHAPE("VirtualSize",    0, c_uint32()),
        SHAPE("VirtualAddress", 0, c_uint32()),
        SHAPE("RawDataSize",  0, c_uint32()),
        SHAPE("PointerToRawData", 0, c_uint32()),
        SHAPE("PointerToRelocations", 0, c_uint32()),
        SHAPE("PointerToLinenumbers", 0, c_uint32()),
        SHAPE("NumberOfRelocations", 0, c_uint16()),
        SHAPE("NumberOfLinenumbers", 0, c_uint16()),
        SHAPE("Characteristics", 0, c_uint32()) ]

ImageDataDirectory = [
        SHAPE("VirtualAddress",     0, c_uint32()),
        SHAPE("Size",               0, c_uint32()) ]

ImageExportDirectory = [
        SHAPE("Characteristics", 0, c_uint32()),
        SHAPE("TimeDateStamp", 0, n_ctime()),
        SHAPE("MajorVersion", 0, c_uint16()),
        SHAPE("MinorVersion", 0, c_uint16()),
        SHAPE("Name", 0, c_uint32()),
        SHAPE("Base", 0, c_uint32()),
        SHAPE("NumberOfFunctions", 0, c_uint32()),
        SHAPE("NumberOfNames", 0, c_uint32()),
        SHAPE("FunctionsAddress", 0, c_uint32()),
        SHAPE("NamesAddress", 0, c_uint32()),
        SHAPE("NameOrdinalsAddress", 0, c_uint32())
        ]

ImageImportDescriptor = [
        SHAPE("Characteristics", 0, c_uint32()),
        SHAPE("TimeDateStamp", 0, n_ctime()),
        SHAPE("ForwarderChain", 0, c_uint32()),
        SHAPE("Name", 0, c_uint32()),
        SHAPE("FirstThunk", 0, c_uint32())
        ]

ImageDebugDirectory = [
        SHAPE("Characteristics",  0, c_uint32()),
        SHAPE("TimeDateStamp",    0, n_ctime()),
        SHAPE("MajorVersion",     0, c_uint16()),
        SHAPE("MinorVersion",     0, c_uint16()),
        SHAPE("Type",             0, c_uint32()),
        SHAPE("DataSize",         0, c_uint32()),
        SHAPE("AddrOfRawData",    0, c_uint32()),
        SHAPE("PointerToRawData", 0, c_uint32()) ]

ResourceDirectoryString = [
        SHAPE("Length", 0,  c_uint16()),
        SHAPE("Data",   0,  n_string(size="Length", isUnicode=True)) ]

ResourceDataEntry = [
        SHAPE("DataRVA",        0, c_uint32()),
        SHAPE("DataEntrySize",  0, c_uint32()),
        SHAPE("Codepage",       0, c_uint32()),
        SHAPE("Reserved",       0, c_uint32(0)) ]

ResourceDirectoryNameEntry = [
        SHAPE("NameRVA",        0, c_uint32()),
        SHAPE("DataEntryRVA",   0, c_uint32()),
        ASSIGN("isDataEntry",       lambda pf, ctx: 0 == (ctx.DataEntryRVA & 0x80000000)),
        ASSIGN("subdirectoryRVA",   lambda pf, ctx: ctx.DataEntryRVA & 0x7fffffff) ]

ResourceDirectoryIdEntry = [
        SHAPE("Id",        0, c_uint32()),
        SHAPE("DataEntryRVA",   0, c_uint32()),
        ASSIGN("isDataEntry",       lambda pf, ctx: 0 == (ctx.DataEntryRVA & 0x80000000)),
        ASSIGN("subdirectoryRVA",   lambda pf, ctx: ctx.DataEntryRVA & 0x7fffffff) ]

ImageResourceDirectory = [
        SHAPE("Characteristics",  0, c_uint32()),
        SHAPE("TimeDateStamp",    0, n_ctime()),
        SHAPE("MajorVersion",     0, c_uint16()),
        SHAPE("MinorVersion",     0, c_uint16()),
        SHAPE("NumOfNamedEntries", 0, c_uint16()),
        SHAPE("NumOfIdEntries",   0, c_uint16()),
        SHAPE("NamedEntries",   0,
            n_array("NumOfNamedEntries",  n_struct, (ResourceDirectoryNameEntry,))),
        SHAPE("IdEntries",   0,
            n_array("NumOfIdEntries",     n_struct, (ResourceDirectoryIdEntry,)))]

RESOURCE_TYPES = {
         1  : "CURSOR",
         2  : "BITMAP",
         3  : "ICON",
         4  : "MENU",
         5  : "DIALOG",
         6  : "STRING",
         7  : "FONTDIR",
         8  : "FONT",
         9  : "ACCELERATOR",
        10  : "RCDATA",
        11  : "MESSAGETABLE",
        16  : "VERSION" }

ResourceVersionInfo = [
        SHAPE("VersionLength",  0,  c_uint16()),
        SHAPE("ValueLength",    0,  c_uint16()),
        SHAPE("dataType",       0,  c_uint16([0,1])),
        SHAPE("VsVersionInfoStr",   0,  n_string(fixedValue="VS_VERSION_INFO", isUnicode=True)),
        SHAPE("Algin",          0,  c_uint32(0)),
        SHAPE("Vs_FixedFileInfo",   0,  c_uint32(0xfeef04bd)) ]

def getAllResData(pe, offset=0, isDir=True):
    resAddr = None
    for item in pe.Sections:
        item = item.Item
        if item.Name.startswith(b'.rsrc\x00'):
            resAddr = item.PointerToRawData
    if None == resAddr:
        raise Exception("Can't find resources data")
    if isDir:
        res = next(p.search(ImageResourceDirectory, resAddr+offset))
    else:
        res = next(p.search(ResourceDataEntry, resAddr+offset))
        print(res)
        addr = res.DataRVA - pe.OptionalHeader.ResDir.VirtualAddress + resAddr
        data = m.readMemory(res.DataRVA, res.DataEntrySize)
        print(DATA(data))
        print('+' * 20)
        return
    print(res)
    print('-' * 20)
    for i, item in enumerate(res.NamedEntries):
        print(i,'.')
        item = item.Item
        if item.isDataEntry:
            getAllResData(resAddr, pe, item.subdirectoryRVA, False)
        else:
            getAllResData(resAddr, pe, item.subdirectoryRVA, True)
    for i, item in enumerate(res.IdEntries):
        print('%d, .' % i)
        item = item.Item
        if item.isDataEntry:
            getAllResData(resAddr, pe, item.subdirectoryRVA, False)
        else:
            getAllResData(resAddr, pe, item.subdirectoryRVA, True)

ImageOptionalHeader = [
        SHAPE("Magic",              0,  c_uint16(list(VALID_PE_FORMATS.keys()))),
        SHAPE("MajorLinkerVersion", 0,  BYTE()),
        SHAPE("MinorLinkerVersion", 0,  BYTE()),
        SHAPE("CodeSize",         0,  c_uint32()),
        SHAPE("InitializedDataSize", 0, c_uint32()),
        SHAPE("UninitializedDataSize", 0, c_uint32()),
        SHAPE("EntryPointAddress", 0, c_uint32()),
        SHAPE("BaseOfCode",         0, c_uint32()),
        SHAPE("BaseOfDataImageBase", 0, n_switch( "Magic",
            {
                PE32_MAGIC  : [
                    SHAPE("BaseOfData",         0, c_uint32()),
                    SHAPE("ImageBase",          0, c_uint32()) ],
                PE32P_MAGIC : [
                    SHAPE("ImageBase",          0, c_uint64()) ],
                "default" : [
                    SHAPE("ImageBase",          0, c_uint64()) ] }) ),
        SHAPE("SectionAlignment",   0, c_uint32()), #list(VALID_SECTION_ALGINMENTS.keys()))),
        SHAPE("FileAlignment",      0, c_uint32()),
        SHAPE("MajorOSVersion", 0, c_uint16()),
        SHAPE("MinorOSVersion", 0, c_uint16()),
        SHAPE("MajorImageVer",  0, c_uint16()),
        SHAPE("MinorImageVer",  0, c_uint16()),
        SHAPE("MajorSubsystemVer", 0, c_uint16()),
        SHAPE("MinorSubsystemVer", 0, c_uint16()),
        SHAPE("Win32VersionValue",  0, c_uint32()),
        SHAPE("ImageSize",        0, c_uint32()),
        SHAPE("HeadersSize",      0, c_uint32()),
        SHAPE("CheckSum",           0, c_uint32()),
        SHAPE("Subsystem",          0, c_uint16(list(WINDOWS_SUBSYSTEMS.keys()))),
        SHAPE("DllCharacteristics", 0, n_flags(DLL_CHARACTERISTICS_FALGS, size=2)),
        SHAPE("Stack", 0, n_switch( lambda ctx: ctx.Magic,
            {
                PE32_MAGIC  : [
                    SHAPE("StackReserveSize", 0, c_uint32()),
                    SHAPE("StackCommitSize",  0, c_uint32()),
                    SHAPE("HeapReserveSize",  0, c_uint32()),
                    SHAPE("HeapCommitSize",   0, c_uint32()) ],
                PE32P_MAGIC  : [
                    SHAPE("StackReserveSize", 0, c_uint64()),
                    SHAPE("StackCommitSize",  0, c_uint64()),
                    SHAPE("HeapReserveSize",  0, c_uint64()),
                    SHAPE("HeapCommitSize",   0, c_uint64()) ]
                }) ),
        SHAPE("LoaderFlags",        0, c_uint32(0)),
        SHAPE("NumOfRvaAndSizes", 0, c_uint32()),
        SHAPE("ExportDir",      0, n_struct(ImageDataDirectory)),
        SHAPE("ImportDir",      0, n_struct(ImageDataDirectory)),
        SHAPE("ResDir",         0, n_struct(ImageDataDirectory)),
        SHAPE("ExceptionDir",   0, n_struct(ImageDataDirectory)),
        SHAPE("SecurityDir",    0, n_struct(ImageDataDirectory)),
        SHAPE("BaserelocDir",   0, n_struct(ImageDataDirectory)),
        SHAPE("DebugDir",       0, n_struct(ImageDataDirectory)),
        SHAPE("ArchDir",        0, n_struct(ImageDataDirectory)),
        SHAPE("GlobalsDir",     0, n_struct(ImageDataDirectory)),
        SHAPE("TLSDir",         0, n_struct(ImageDataDirectory)),
        SHAPE("LoadConfDir",    0, n_struct(ImageDataDirectory)),
        SHAPE("BoundImportDir", 0, n_struct(ImageDataDirectory)),
        SHAPE("IATDir",         0, n_struct(ImageDataDirectory)),
        SHAPE("DelayImportDir", 0, n_struct(ImageDataDirectory)),
        SHAPE("CLRRuntimeDir",  0, n_struct(ImageDataDirectory)),
        SHAPE("ReservedDir",    0, n_struct(ImageDataDirectory)) ]

ImageNtHeaders = [
        SHAPE("Signature", 0, n_string(fixedValue=b'PE\x00\x00')),
        SHAPE("FileHeader", 0, n_struct(ImageFileHeader)),
        SHAPE("OptionalHeader", 0, n_struct(ImageOptionalHeader)),
        SHAPE("Sections", 0, \
                n_array(lambda ctx: ctx.FileHeader.NumberOfSections, n_struct, [ImageSectionHeader])) ]

ImageDosHeader = [
        SHAPE("e_magic", 0, n_string(fixedValue=b"MZ")),
        SHAPE("e_cblp", 0, c_uint16()),
        SHAPE("e_cp", 0, c_uint16()),
        SHAPE("e_crlc", 0, c_uint16()),
        SHAPE("e_cparhdr", 0, c_uint16()),
        SHAPE("e_minalloc", 0, c_uint16()),
        SHAPE("e_maxalloc", 0, c_uint16()),
        SHAPE("e_ss", 0, c_uint16()),
        SHAPE("e_sp", 0, c_uint16()),
        SHAPE("e_csum", 0, c_uint16()),
        SHAPE("e_ip", 0, c_uint16()),
        SHAPE("e_cs", 0, c_uint16()),
        SHAPE("e_lfarlc", 0, c_uint16()),
        SHAPE("e_ovno", 0, c_uint16()),
        SHAPE("e_res", 0, n_array(4, c_uint16, ())),
        SHAPE("e_oemid", 0, c_uint16()),
        SHAPE("e_oeminfo", 0, c_uint16()),
        SHAPE("e_res2", 0, n_array(10, c_uint16, ())),
        SHAPE("e_lfanew", 0, c_uint32()),
        SHAPE("PE", lambda ctx, addr: (addr + ctx.e_lfanew, ctx.e_lfanew), n_struct(ImageNtHeaders))
        ]

#def getImports(baseCtx):
#    IMPORT_DESCRIPTOR_SIZE = 5 * 4
#    importsPat = []
#    importsAddr = baseCtx.PE.OptionalHeader.AddressOfImports
#    importsSize = baseCtx.PE.OptionalHeader.ImportDir.Size
#    numDescriptors = importsSize / IMPORT_DESCRIPTOR_SIZE
#    for i in range(numDescriptors):
#        importsPat.append(
#                SHAPE("Import%06x" % i, 0, n_struct(ImageImportDescriptor)))


