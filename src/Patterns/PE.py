
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
    0x0040  : "DYNAMIC_BASE",
    0x0080  : "FORCE_INTEGRITY",
    0x0100  : "NX_COMPAT",
    0x0200  : "NO_ISOLATION",
    0x0400  : "NO_SEH",
    0x0800  : "NO_BIND",
    0x2000  : "WDM_DRIVER",
    0x8000  : "TERMINAL_SERVER_AWARE" }

ImageFileHeader = [
        SHAPE("Machine",            0, WORD(VALID_MACHINE_TYPES.keys())),
        SHAPE("NumberOfSections",   0, WORD()),
        SHAPE("TimeDateStamp",      0, CTIME()),
        SHAPE("PointerToSymTable",  0, DWORD()),
        SHAPE("NumberOfSymbols",    0, DWORD()),
        SHAPE("OptionalHeaderSize", 0, WORD()),
        SHAPE("Characteristics",    0, WORD()) ]

ImageSectionHeader = [
        SHAPE("Name",           0, BUFFER(size=8)),
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

ImageDebugDirectory = [
        SHAPE("Characteristics",  0, DWORD()),
        SHAPE("TimeDateStamp",    0, CTIME()),
        SHAPE("MajorVersion",     0, WORD()),
        SHAPE("MinorVersion",     0, WORD()),
        SHAPE("Type",             0, DWORD()),
        SHAPE("DataSize",         0, DWORD()),
        SHAPE("AddrOfRawData",    0, DWORD()),
        SHAPE("PointerToRawData", 0, DWORD()) ]

ResourceDirectoryString = [
        SHAPE("Length", 0,  WORD()),
        SHAPE("Data",   0,  STRING(size="Length", isUnicode=True)) ]

ResourceDataEntry = [
        SHAPE("DataRVA",        0, DWORD()),
        SHAPE("DataEntrySize",  0, DWORD()),
        SHAPE("Codepage",       0, DWORD()),
        SHAPE("Reserved",       0, DWORD(0)) ]

ResourceDirectoryNameEntry = [
        SHAPE("NameRVA",        0, DWORD()),
        SHAPE("DataEntryRVA",   0, DWORD()),
        ASSIGN("isDataEntry",       lambda pf, ctx: 0 == (ctx.DataEntryRVA & 0x80000000)),
        ASSIGN("subdirectoryRVA",   lambda pf, ctx: ctx.DataEntryRVA & 0x7fffffff) ]

ResourceDirectoryIdEntry = [
        SHAPE("Id",        0, DWORD()),
        SHAPE("DataEntryRVA",   0, DWORD()),
        ASSIGN("isDataEntry",       lambda pf, ctx: 0 == (ctx.DataEntryRVA & 0x80000000)),
        ASSIGN("subdirectoryRVA",   lambda pf, ctx: ctx.DataEntryRVA & 0x7fffffff) ]

ImageResourceDirectory = [
        SHAPE("Characteristics",  0, DWORD()),
        SHAPE("TimeDateStamp",    0, CTIME()),
        SHAPE("MajorVersion",     0, WORD()),
        SHAPE("MinorVersion",     0, WORD()),
        SHAPE("NumOfNamedEntries", 0, WORD()),
        SHAPE("NumOfIdEntries",   0, WORD()),
        SHAPE("NamedEntries",   0,  
            ARRAY("NumOfNamedEntries",  STRUCT, (ResourceDirectoryNameEntry,))),
        SHAPE("IdEntries",   0,  
            ARRAY("NumOfIdEntries",     STRUCT, (ResourceDirectoryIdEntry,)))]

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
        SHAPE("VersionLength",  0,  WORD()),
        SHAPE("ValueLength",    0,  WORD()),
        SHAPE("dataType",       0,  WORD([0,1])),
        SHAPE("VsVersionInfoStr",   0,  STRING(fixedValue="VS_VERSION_INFO", isUnicode=True)),
        SHAPE("Algin",          0,  DWORD(0)),
        SHAPE("Vs_FixedFileInfo",   0,  DWORD(0xfeef04bd)) ]

def getAllResData(pe, offset=0, isDir=True):
    resAddr = None
    for item in pe.Sections:
        item = item.Item
        if item.Name.startswith('.rsrc\x00'):
            resAddr = item.PointerToRawData
    if None == resAddr:
        raise Exception("Can't find resources data")
    if isDir:
        res = p.search(ImageResourceDirectory, resAddr+offset).next()
    else:
        res = p.search(ResourceDataEntry, resAddr+offset).next()
        print res
        addr = res.DataRVA - pe.OptionalHeader.ResDir.VirtualAddress + resAddr
        data = m.readMemory(res.DataRVA, res.DataEntrySize)
        print DATA(data)
        print '+' * 20
        return
    print res
    print '-' * 20
    for i, item in enumerate(res.NamedEntries):
        print i,'.'
        item = item.Item
        if item.isDataEntry:
            getAllResData(resAddr, pe, item.subdirectoryRVA, False)
        else:
            getAllResData(resAddr, pe, item.subdirectoryRVA, True)
    for i, item in enumerate(res.IdEntries):
        print i,'.'
        item = item.Item
        if item.isDataEntry:
            getAllResData(resAddr, pe, item.subdirectoryRVA, False)
        else:
            getAllResData(resAddr, pe, item.subdirectoryRVA, True)

ImageOptionalHeader = [
        SHAPE("Magic",              0,  WORD(VALID_PE_FORMATS.keys())),
        SHAPE("MajorLinkerVersion", 0,  BYTE()),
        SHAPE("MinorLinkerVersion", 0,  BYTE()),
        SHAPE("CodeSize",         0,  DWORD()),
        SHAPE("InitializedDataSize", 0, DWORD()),
        SHAPE("UninitializedDataSize", 0, DWORD()),
        SHAPE("EntryPointAddress", 0, DWORD()),
        SHAPE("BaseOfCode",         0, DWORD()),
        SHAPE("BaseOfDataImageBase", 0, SWITCH( "Magic",
            {
                PE32_MAGIC  : [
                    SHAPE("BaseOfData",         0, DWORD()),
                    SHAPE("ImageBase",          0, DWORD()) ],
                PE32P_MAGIC : [
                    SHAPE("ImageBase",          0, QWORD()) ],
                "default" : [
                    SHAPE("ImageBase",          0, QWORD()) ] }) ),
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
        SHAPE("Subsystem",          0, WORD(WINDOWS_SUBSYSTEMS.keys())),
        SHAPE("DllCharacteristics", 0, FLAGS(DLL_CHARACTERISTICS_FALGS, size=2)),
        SHAPE("Stack", 0, SWITCH( lambda ctx: ctx.Magic,
            {
                PE32_MAGIC  : [
                    SHAPE("StackReserveSize", 0, DWORD()),
                    SHAPE("StackCommitSize",  0, DWORD()),
                    SHAPE("HeapReserveSize",  0, DWORD()),
                    SHAPE("HeapCommitSize",   0, DWORD()) ],
                PE32P_MAGIC  : [
                    SHAPE("StackReserveSize", 0, QWORD()),
                    SHAPE("StackCommitSize",  0, QWORD()),
                    SHAPE("HeapReserveSize",  0, QWORD()),
                    SHAPE("HeapCommitSize",   0, QWORD()) ]
                }) ),
        SHAPE("LoaderFlags",        0, DWORD(0)),
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
        SHAPE("CLRRuntimeDir",  0, STRUCT(ImageDataDirectory)),
        SHAPE("ReservedDir",    0, STRUCT(ImageDataDirectory)) ]

ImageNtHeaders = [
        SHAPE("Signature", 0, STRING(fixedValue='PE\x00\x00')),
        SHAPE("FileHeader", 0, STRUCT(ImageFileHeader)),
        SHAPE("OptionalHeader", 0, STRUCT(ImageOptionalHeader)),
        SHAPE("Sections", 0, \
                ARRAY(lambda ctx: ctx.FileHeader.NumberOfSections, STRUCT, [ImageSectionHeader])) ]

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


