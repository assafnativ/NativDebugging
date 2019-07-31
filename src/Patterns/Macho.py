
from .Finder import *

# Refs:
#   SDKs/iPhoneOS6.0.sdk/usr/include/mach-o/loader.h

VALID_MAGICS = {
    0xfeedface : 'MH_MAGIC',
    0xfeedfacf : 'MH_MAGIC64',
    0xcefaedfe : 'MH_CIGAM',
    0xcffaedfe : 'MH_CIGAM64' }

VALID_CPU_TYPES = {
    0xffffffff : 'CPU_TYPE_ANY',
    0x00000001 : 'CPU_TYPE_VAX',
    0x00000006 : 'CPU_TYPE_MC680x0',
    0x00000007 : 'CPU_TYPE_x86',
    0x01000007 : 'CPU_TYPE_X86_64',
    0x00000008 : 'CPU_TYPE_MIPS',
    0x0000000a : 'CPU_TYPE_MC98000',
    0x0000000b : 'CPU_TYPE_HPPA',
    0x0000000c : 'CPU_TYPE_ARM',
    0x0000000d : 'CPU_TYPE_MC88000',
    0x0000000e : 'CPU_TYPE_SPARC',
    0x0000000f : 'CPU_TYPE_I860',
    0x00000010 : 'CPU_TYPE_ALPHA',
    0x00000012 : 'CPU_TYPE_POWERPC',
    0x01000012 : 'CPU_TYPE_POWERPC64' }

VALID_FILE_TYPES = {
        0x1             : ('MH_OBJECT', 'relocatable object file'),
        0x2             : ('MH_EXECUTE','demand paged executable file'),
        0x3             : ('MH_FVMLIB', 'fixed VM shared library file'),
        0x4             : ('MH_CORE     ',      'core file'),
        0x5             : ('MH_PRELOAD','preloaded executable file'),
        0x6             : ('MH_DYLIB',  'dynamically bound shared library'),
        0x7             : ('MH_DYLINKER','dynamic link editor'),
        0x8             : ('MH_BUNDLE',  'dynamically bound bundle file'),
        0x9             : ('MH_DYLIB_STUB',     'shared library stub for static linking only, no section contents'),
        0xa             : ('MH_DSYM     ','companion file with only debug sections'),
        0xb             : ('MH_KEXT_BUNDLE','x86_64 kexts') }


# Mach-O header flags defines:
FLAGS_DESC = {
        0x1 :       ("MH_NOUNDEFS", "the object file has no undefined references"),
        0x2 :       ("MH_INCRLINK", "the object file is the output of an incremental link against a base file and can't be link edited again"),
        0x4 :       ("MH_DYLDLINK", "the object file is input for the dynamic linker and can't be staticly link edited again"),
        0x8 :       ("MH_BINDATLOAD", "the object file's undefined references are bound by the dynamic linker when loaded."),
        0x10:       ("MH_PREBOUND", "the file has its dynamic undefined references prebound."),
        0x20:       ("MH_SPLIT_SEGS", "the file has its read-only and read-write segments split"),
        0x40:       ("MH_LAZY_INIT", "the shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete)"),
        0x80:       ("MH_TWOLEVEL", "the image is using two-level name space bindings"),
        0x100:      ("MH_FORCE_FLAT", "the executable is forcing all images to use flat name space bindings"),
        0x200:      ("MH_NOMULTIDEFS", "this umbrella guarantees no multiple defintions of symbols in its sub-images so the two-level namespace hints can always be used."),
        0x400:      ("MH_NOFIXPREBINDING", "do not have dyld notify the prebinding agent about this executable"),
        0x800:      ("MH_PREBINDABLE ", "the binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is not set."),
        0x1000:     ("MH_ALLMODSBOUND", "indicates that this binary binds to all two-level namespace modules of its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL are both set. "),
        0x2000:     ("MH_SUBSECTIONS_VIA_SYMBOLS ", "safe to divide up the sections into sub-sections via symbols for dead code stripping"),
        0x4000:     ("MH_CANONICAL   ", "the binary has been canonicalized via the unprebind operation"),
        0x8000:     ("MH_WEAK_DEFINES", "the final linked image contains external weak symbols"),
        0x10000:    ("MH_BINDS_TO_WEAK", "the final linked image uses weak symbols"),
        0x20000:    ("MH_ALLOW_STACK_EXECUTION", "When this bit is set, all stacks in the task will be given stack execution privilege.  Only used in MH_EXECUTE filetypes."),
        0x40000:    ("MH_ROOT_SAFE", "When this bit is set, the binary declares it is safe for use in processes with uid zero"),
        0x80000:    ("MH_SETUID_SAFE", "When this bit is set, the binary declares it is safe for use in processes when issetugid() is true"),
        0x100000:   ("MH_NO_REEXPORTED_DYLIBS", "When this bit is set on a dylib, the static linker does not need to examine dependent dylibs to see if any are re-exported"),
        0x200000:   ("MH_PIE", "When this bit is set, the OS will load the main executable at a random address.  Only used in MH_EXECUTE filetypes."),
        0x400000:   ("MH_DEAD_STRIPPABLE_DYLIB", "Only for use on dylibs.  When linking against a dylib that has this bit set, the static linker will automatically not create a LC_LOAD_DYLIB load command to the dylib if no symbols are being referenced from the dylib."),
        0x800000:   ("MH_HAS_TLV_DESCRIPTORS", "Contains a section of type S_THREAD_LOCAL_VARIABLES"),
        0x1000000:  ("MH_NO_HEAP_EXECUTION", "When this bit is set, the OS will run the main executable with a non-executable heap even on platforms (e.g. i386) that don't require it. Only used in MH_EXECUTE filetypes.") }

# Mach-O commands ids:
MACHO_COMMANDS = {
        0x80000000: ("LC_REQ_DYLD", ""),
        0x1     : ("LC_SEGMENT", "segment of this file to be mapped"),
        0x2     : ("LC_SYMTAB", "link-edit stab symbol table info"),
        0x3     : ("LC_SYMSEG", "link-edit gdb symbol table info (obsolete)"),
        0x4     : ("LC_THREAD", "thread"),
        0x5     : ("LC_UNIXTHREAD", "unix thread (includes a stack)"),
        0x6     : ("LC_LOADFVMLIB", "load a specified fixed VM shared library"),
        0x7     : ("LC_IDFVMLIB", "fixed VM shared library identification"),
        0x8     : ("LC_IDENT", "object identification info (obsolete)"),
        0x9     : ("LC_FVMFILE", "fixed VM file inclusion (internal use)"),
        0xa     : ("LC_PREPAGE", "prepage command (internal use)"),
        0xb     : ("LC_DYSYMTAB", "dynamic link-edit symbol table info"),
        0xc     : ("LC_LOAD_DYLIB", "load a dynamically linked shared library"),
        0xd     : ("LC_ID_DYLIB", "dynamically linked shared lib ident"),
        0xe     : ("LC_LOAD_DYLINKER", "load a dynamic linker"),
        0xf     : ("LC_ID_DYLINKER", "dynamic linker identification"),
        0x10    : ("LC_PREBOUND_DYLIB", "modules prebound for a dynamically"),
        0x11    : ("LC_ROUTINES", "image routines"),
        0x12    : ("LC_SUB_FRAMEWORK", "sub framework"),
        0x13    : ("LC_SUB_UMBRELLA", "sub umbrella"),
        0x14    : ("LC_SUB_CLIENT", "sub client"),
        0x15    : ("LC_SUB_LIBRARY ", "sub library"),
        0x16    : ("LC_TWOLEVEL_HINTS", "two-level namespace lookup hints"),
        0x17    : ("LC_PREBIND_CKSUM ", "prebind checksum"),
        0x80000018 : ("LC_LOAD_WEAK_DYLIB", ""),
        0x19    : ("LC_SEGMENT_64", "64-bit segment of this file to be mapped "),
        0x1a    : ("LC_ROUTINES_64", "64-bit image routines "),
        0x1b    : ("LC_UUID", "the uuid "),
        0x8000001c : ("LC_RPATH", "runpath additions"),
        0x1d    : ("LC_CODE_SIGNATURE", "local of code signature "),
        0x1e : ("LC_SEGMENT_SPLIT_INFO", "local of info to split segments "),
        0x8000001f : ("LC_REEXPORT_DYLIB", "load and re-export dylib") ,
        0x20    : ("LC_LAZY_LOAD_DYLIB", "delay load of dylib until first use "),
        0x21    : ("LC_ENCRYPTION_INFO", "encrypted segment information "),
        0x22    : ("LC_DYLD_INFO", "compressed dyld information "),
        0x80000022: ("LC_DYLD_INFO_ONLY", "compressed dyld information only"),
        0x80000023 : ("LC_LOAD_UPWARD_DYLIB", "load upward dylib"),
        0x24   : ("LC_VERSION_MIN_MACOSX", "build for MacOSX min OS version "),
        0x25 : ("LC_VERSION_MIN_IPHONEOS", "build for iPhoneOS min OS version "),
        0x26 : ("LC_FUNCTION_STARTS", "compressed table of function start addresses "),
        0x27 : ("LC_DYLD_ENVIRONMENT", "string for dyld to treat like environment variable "),
        0x80000028: ("LC_MAIN", "replacement for LC_UNIXTHREAD"),
        0x29 : ("LC_DATA_IN_CODE", "table of non-instructions in __text "),
        0x2A : ("LC_SOURCE_VERSION", "source version used to build binary "),
        0x2B : ("LC_DYLIB_CODE_SIGN_DRS", "Code signing DRs copied from linked dylibs ") }
MACHO_COMMANDS_IDS = dict([(x[1][0], x[0]) for x in MACHO_COMMANDS.items()])


def GET_CMD_SIZE(context):
    return context._parent.size - context._parent.OffsetOfcmd_data

MACHO_COMMAND_DEFAULT_PATTERN = [
        SHAPE("data",   0,  BUFFER(size=GET_CMD_SIZE))
        ]

def IS_EXTENDED_NAME(context):
    return context.name_offset == 0x18

def EXTENDED_NAME_LENGTH(context):
    return context._parent._parent.size - context._parent.name_offset

MACHO_DYLIB_COMMAND_PATTERN = [
        SHAPE("name_offset",            0,  n_uint32()),
        SHAPE("timestamp",              0,  n_ctime()),
        SHAPE("current_version",        0,  n_uint32()),
        SHAPE("compatibility_version",  0,  n_uint32()),
        SHAPE("extended_name",          0,  n_switch(IS_EXTENDED_NAME, {
            True:  [SHAPE("name",       0,  n_string(size=EXTENDED_NAME_LENGTH, isPrintable=False))],
            False: []}))]

MACHO_ENCRYPTION_INFO_COMMAND_PATTERN = [
        SHAPE("cryptooff",  0,  n_uint32()),
        SHAPE("cryptsize",  0,  n_uint32()),
        SHAPE("cryptid",    0,  n_uint32()) ]

MACHO_SOURCE_VERSION_COMMAND_PATTERN = [
        SHAPE("version",    0,  n_uint64()) ]

MACHO_DATA_COMMAND_PATTERN = [
        SHAPE("dataoff",    0,  n_uint32()),
        SHAPE("datasize",   0,  n_uint32()) ]

MACHO_CMD_PATTERN = [
        SHAPE("type",   0,  n_uint32(list(MACHO_COMMANDS.keys()))),
        SHAPE("size",   0,  n_uint32()),
        SHAPE("cmd_data", 0, n_switch("type", {
            MACHO_COMMANDS_IDS["LC_LOAD_DYLIB"]     : MACHO_DYLIB_COMMAND_PATTERN,
            MACHO_COMMANDS_IDS["LC_LOAD_WEAK_DYLIB"]: MACHO_DYLIB_COMMAND_PATTERN,
            MACHO_COMMANDS_IDS["LC_REEXPORT_DYLIB"] : MACHO_DYLIB_COMMAND_PATTERN,
            MACHO_COMMANDS_IDS["LC_CODE_SIGNATURE"] : MACHO_DATA_COMMAND_PATTERN,
            MACHO_COMMANDS_IDS["LC_SEGMENT_SPLIT_INFO"]     : MACHO_DATA_COMMAND_PATTERN,
            MACHO_COMMANDS_IDS["LC_FUNCTION_STARTS"]        : MACHO_DATA_COMMAND_PATTERN,
            MACHO_COMMANDS_IDS["LC_DATA_IN_CODE"]           : MACHO_DATA_COMMAND_PATTERN,
            MACHO_COMMANDS_IDS["LC_DYLIB_CODE_SIGN_DRS"]    : MACHO_DATA_COMMAND_PATTERN,
            MACHO_COMMANDS_IDS["LC_ENCRYPTION_INFO"] : MACHO_ENCRYPTION_INFO_COMMAND_PATTERN,
            "default"   : MACHO_COMMAND_DEFAULT_PATTERN
            })),
        SHAPE("extra_data", 0,  n_buffer(size=lambda context:context.size - 8 - context.SizeOfcmd_data))
        ]

MACHO_HEADER_PATTERN = [
        SHAPE("magic",      0,  n_uint32(list(VALID_MAGICS.keys()))),
        SHAPE("cputtype",   0,  n_uint32(list(VALID_CPU_TYPES.keys()))),
        SHAPE("cpusubtype", 0,  n_uint32()),
        SHAPE("filetype",   0,  n_uint32(list(VALID_FILE_TYPES.keys()))),
        SHAPE("ncmds",      0,  n_uint32()),
        SHAPE("sizeofcmds", 0,  n_uint32()),
        SHAPE("flags",      0,  n_flags(FLAGS_DESC, size=4)),
        SHAPE("cmds",       0,  n_array("ncmds", STRUCT, (MACHO_CMD_PATTERN,))) ]

