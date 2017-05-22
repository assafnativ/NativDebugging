
from ..Interfaces import ReadError
from ..MemReaderBase import *
from ..GUIDisplayBase import *
from collections import namedtuple
from ..ObjectWithStream import ObjectWithStream

try:
    import distorm3
    IS_DISASSEMBLER_FOUND = True
except ImportError as e:
    IS_DISASSEMBLER_FOUND = False

class MiniDump( MemReaderBase, GUIDisplayBase ):
    def __init__(self, dumpFile, isVerbose=False):
        print("Loading mini dump")
        MemReaderBase.__init__(self)
        self._ENDIANITY = '<'
        self.stream = ObjectWithStream(dumpFile)
        magic = self.stream.read(4)
        if 'MDMP' != magic:
            raise Exception("Wrong magic in MiniDump {%r}", magic)
        self.dumpVersion = self.stream.readUInt32()
        self.numStreams = self.stream.readUInt32()
        streamDirRVA = self.stream.readUInt32()
        checksum = self.stream.readUInt32()
        self.dumpTimeStamp = self.stream.readUInt32()
        self.dumpFlags = self.stream.readUInt64()
        self.comments = []
        self.directories = []
        self.stream.seek(streamDirRVA)
        self.memoryList = None
        for streamNumber in xrange(self.numStreams):
            self.directories.append((self.stream.readUInt32(),) + self._readLocationDescriptor())
        for streamType, length, rva in self.directories:
            self._parseDirectory(streamType, rva, length)
        self._DATA = {}
        self._REGIONS = []
        if self.memoryList:
            for mem in self.memoryList:
                self.stream.seek(mem.memory.rva)
                self._DATA[mem.startOfMemoryRange] = self.stream.read(mem.memory.dataSize)
                self._REGIONS.append((mem.startOfMemoryRange, mem.startOfMemoryRange + mem.memory.dataSize))
        else:
            self.stream.seek(self.memory64List.baseRva)
            for mem in self.memory64List.memoryRanges:
                self._DATA[mem.startOfMemoryRange] = self.stream.read(mem.dataSize)
                self._REGIONS.append((mem.startOfMemoryRange, mem.startOfMemoryRange + mem.dataSize))
        self._DEFAULT_DATA_SIZE = 4
        if 0 == self.systemInfo.processorArchitecture:
            self._POINTER_SIZE = 4
        elif self.systemInfo.processorArchitecture in [9, 6]:
            self._POINTER_SIZE = 8
        else:
            self._POINTER_SIZE = 4

    def _parseDirectory(self, streamType, rva, length):
        self.stream.seek(rva)
        if 3 == streamType:
            self.threadList = self._readThreadList()
        elif 4 == streamType:
            self.moduleList = self._readModuleList()
        elif 5 == streamType:
            self.memoryList = self._readMemoryList()
        elif 6 == streamType:
            self.exceptionInfo = self._readException()
        elif 7 == streamType:
            self.systemInfo = self._readSystemInfo()
        elif 8 == streamType:
            self.threadExList = self._readThreadExList()
        elif 9 == streamType:
            self.memory64List = self._readMemory64List()
        elif 10 == streamType:
            self.comments.append(self.stream.read(length))
        elif 11 == streamType:
            self.comments.append(self.stream.read(length).decode('UTF16'))
        elif 12 == streamType:
            self.handleData = self._readHandleData()
        elif 13 == streamType:
            self.functionTable = self._readFunctionTable()
        elif 14 == streamType:
            self.unloadedModuleList = self._readUnloadedModuleList()
        elif 15 == streamType:
            self.miscInfo = self._readMiscInfo()
            self.stream.seek(rva + length)
        elif 16 == streamType:
            self.memoryInfoList = self._readMemoryInfoList()
        elif 17 == streamType:
            self.threadInfoList = self._readThreadInfoList()
        elif 18 == streamType:
            self.handleOperationList = self._readHandleOperationList()
        elif 19 == streamType:
            self.token = self._readToken()
        elif streamType in [21, 22]:
            data = self.stream.read(length)
            pass
#        elif 0x8000 == streamType:
#            self._readceStreamNull()
#        elif 0x8001 == streamType:
#            self._readceStreamSystemInfo()
#        elif 0x8002 == streamType:
#            self._readceStreamException()
#        elif 0x8003 == streamType:
#            self._readceStreamModuleList()
#        elif 0x8004 == streamType:
#            self._readceStreamProcessList()
#        elif 0x8005 == streamType:
#            self._readceStreamThreadList()
#        elif 0x8006 == streamType:
#            self._readceStreamThreadContextList()
#        elif 0x8007 == streamType:
#            self._readceStreamThreadCallStackList()
#        elif 0x8008 == streamType:
#            self._readceStreamMemoryVirtualList()
#        elif 0x8009 == streamType:
#            self._readceStreamMemoryPhysicalList()
#        elif 0x800A == streamType:
#            self._readceStreamBucketParameters()
#        elif 0x800B == streamType:
#            self._readceStreamProcessModuleMap()
#        elif 0x800C == streamType:
#            self._readceStreamDiagnosisList()
        elif 0xffff == streamType or 0 == streamType:
            if 0 != length:
                raise Exception("Last stream has data")
            return
        else:
            raise Exception("Invalid stream")
        bytesRead = self.stream.tell() - rva
        assert(bytesRead == length)

    def _readThreadList(self):
        numThreads = self.stream.readUInt32()
        threads = []
        for i in xrange(numThreads):
            threads.append(self._readThread())
        return threads

    def _readThreadExList(self):
        numThreads = self.stream.readUInt32()
        threads = []
        for i in xrange(numThreads):
            threads.append(self._readThreadEx())
        return threads

    def _readThread(self):
        return namedtuple('thread', [
            'threadId',
            'suspendCount',
            'priorityClass',
            'priority',
            'teb',
            'stack',
            'threadContext',
            'backingStore'])(
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt64(),
                self._readMemoryDescriptor(),
                self._readLocationDescriptor(),
                None)

    def _readThreadEx(self):
        thread = self._readThread()
        thread.backingStore = self._readLocationDescriptor()
        return thread

    def _readModuleList(self):
        numModules = self.stream.readUInt32()
        modules = []
        for i in xrange(numModules):
            modules.append(self._readModule())
        return modules

    def _readModule(self):
        return namedtuple('module', [
            'baseOfImage',
            'sizeOfImage',
            'checksum',
            'timeDateStamp',
            'moduleName',
            'versionInfo',
            'cvRecrod',
            'miscRecord',
            'reserved0',
            'Reserved1'])(
                self.stream.readUInt64(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self._readStringFrom(self.stream.readUInt32()),
                self._readVSFixedFileInfo(),
                self._readLocationDescriptor(),
                self._readLocationDescriptor(),
                self.stream.readUInt64(),
                self.stream.readUInt64())

    def _readMemoryList(self):
        numMemoryRanges = self.stream.readUInt32()
        memoryRanges = []
        MEMORY_RANGE_TYPE = namedtuple('MEMORY_DESCRIPTOR', ['startOfMemoryRange', 'memory'])
        for i in xrange(numMemoryRanges):
            memoryRanges.append(MEMORY_RANGE_TYPE(
                    self.stream.readUInt64(),
                    self._readLocationDescriptor()))
        return memoryRanges

    def _readMemory64List(self):
        numMemoryRanges = self.stream.readUInt64()
        baseRva = self.stream.readUInt64()
        memoryRanges = []
        MEMORY_DESCRIPTOR_TYPE = namedtuple('MEMORY_DESCRIPTOR', ['startOfMemoryRange', 'dataSize'])
        for i in xrange(numMemoryRanges):
            memoryRanges.append(MEMORY_DESCRIPTOR_TYPE(
                    self.stream.readUInt64(),
                    self.stream.readUInt64()))
        return namedtuple('MEMORY64_LIST', ['baseRva', 'memoryRanges'])(baseRva, memoryRanges)

    def _readException(self):
        return namedtuple('MINIDUMP_EXCEPTION_STREAM', [
            'threadId',
            'alignment',
            'exceptionCode',
            'exceptionFlags',
            'exceptionRecord',
            'exceptionAddress',
            'numberParameters',
            'unusedAlignment',
            'exceptionInformation',
            'threadContext'])(
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt64(),
                    self.stream.readUInt64(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    [
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64(),
                        self.stream.readUInt64() ],
                    self._readLocationDescriptor())

    def _readSystemInfo(self):
        return namedtuple('MINIDUMP_SYSTEM_INFO', [
            'processorArchitecture',
            'processorLevel',
            'processorRevision',
            'numberOfProcessors',
            'productType',
            'majorVersion',
            'minorVersion',
            'buildNumber',
            'platformId',
            'csdVersionRva',
            'suiteMask',
            'reserved2',
            'cpu'])(
                self.stream.readUInt16(),
                self.stream.readUInt16(),
                self.stream.readUInt16(),
                self.stream.readUInt8(),
                self.stream.readUInt8(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt16(),
                self.stream.readUInt16(),
                (
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32()))

    def _readVSFixedFileInfo(self):
        return namedtuple('VS_FIXEDFILEINFO', [
            'signature',
            'structVersion',
            'fileVersionMS',
            'fileVersionLS',
            'productVersionMS',
            'productVersionLS',
            'fileFlagsMask',
            'fileFlags',
            'fileOS',
            'fileType',
            'fileSubType',
            'fileDateMS',
            'fileDateLS'])(
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32())

    def _readHandleData(self):
        pos = self.stream.tell()
        handleData = namedtuple('HANDLE_DATA', [
            'sizeOfHeader',
            'sizeOfDescriptor',
            'numberOfDescriptors',
            'reserved',
            'descriptors'])(
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                [])
        assert(self.stream.tell() - pos == handleData.sizeOfHeader)
        HANDLE_DESCRIPTOR_TYPE = namedtuple('HANDLE_DESCRIPTOR', [
                'handle',
                'typeNameRva',
                'objectNameRva',
                'attributes',
                'grantedAccess',
                'handleCount',
                'pointerCount',
                'objectInfoRva',
                'reserved0'])
        for i in xrange(handleData.numberOfDescriptors):
            if 0x28 == handleData.sizeOfDescriptor:
                handleDescriptor = HANDLE_DESCRIPTOR_TYPE(
                        self.stream.readUInt64(),
                        self.stream.readUInt32(),
                        self.stream.readUInt32(),
                        self.stream.readUInt32(),
                        self.stream.readUInt32(),
                        self.stream.readUInt32(),
                        self.stream.readUInt32(),
                        self.stream.readUInt32(),
                        self.stream.readUInt32())
            else:
                handleDescriptor = HANDLE_DESCRIPTOR_TYPE(
                        self.stream.readUInt64(),
                        self.stream.readUInt32(),
                        self.stream.readUInt32(),
                        self.stream.readUInt32(),
                        self.stream.readUInt32(),
                        self.stream.readUInt32(),
                        self.stream.readUInt32(),
                        None, None)
            handleData.descriptors.append(handleDescriptor)
        return handleData

    def _readFunctionTable(self):
        pos = self.stream.tell()
        functionTable = namedtuple('FUNCTION_TABLE', [
            'sizeOfHeader',
            'sizeOfDescriptor',
            'sizeOfNativeDescriptor',
            'sizeOfFunctionEntry',
            'numberOfDescriptors',
            'sizeOfAlignPad',
            'functions'])(
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                [])
        assert(self.stream.tell() - pos == functionTable.sizeOfHeader)
        FUNCTION_TYPE = namedtuple('FUNCTION', [
                'minimumAddress',
                'maximumAddress',
                'baseAddress',
                'entryCount',
                'sizeOfAlignPad'])
        for i in xrange(functionTable.numberOfDescriptors):
            functionInfo = FUNCTION_TYPE(
                    self.stream.readUInt64(),
                    self.stream.readUInt64(),
                    self.stream.readUInt64(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32())
            functionTable.functions.append(functionInfo)
        return functionTable

    def _readUnloadedModuleLost(self):
        pos = self.stream.tell()
        unloadedModuleList = namedtuple('UNLOADED_MODULE_LIST', [
            'sizeOfHeader',
            'sizeOfEntry',
            'numberOfEntries',
            'modules'])(
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                [])
        assert(self.stream.tell() - pos == unloadedModuleList.sizeOfHeader)
        UNLOADED_MODULE_TYPE = namedtuple('UNLOADED_MODULE', ['baseOfImage', 'sizeOfImage', 'checkSum', 'timeDateStamp', 'name'])
        for i in xrange(unloadedModuleList.numberOfEntries):
            module = UNLOADED_MODULE_TYPE(
                    self.stream.readUInt64(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self._readStringFrom(self.stream.readUInt32()))
            unloadedModuleList.modules.append(module)
        return unloadedModuleList

    def _readMiscInfo(self):
        sizeOfInfo = self.stream.readUInt32()
        MISC_INFO_TYPE = namedtuple('MISC_INFO', [
            'sizeOfInfo',
            'flags1',
            'processId',
            'processCreateTime',
            'processUserTime',
            'processKernelTime',
            'processorMaxMhz',
            'processorCurrentMhz',
            'processorMhzLimit',
            'processorMaxIdleState',
            'processorCurrentIdleState'])
        if 0x2c > sizeOfInfo:
            miscInfo = MISC_INFO_TYPE(
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    None, None, None, None, None)
        else:
            miscInfo = MISC_INFO_TYPE(
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32())
        return miscInfo

    def _readMemoryInfoList(self):
        memoryInfoList = namedtuple('MEMORY_INFO_LIST', [
            'sizeOfHeader',
            'sizeOfEntry',
            'numberOfEntries',
            'memory'])(
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt64(),
                [])
        MEMORY_INFO_TYPE = namedtuple('MEMORY_INFO', ['baseAddress', 'allocationBase', 'allocationProtect', 'alignment1', 'regionSize', 'state', 'protect', 'type', 'alignment2'])
        for i in xrange(memoryInfoList.numberOfEntries):
            memory = MEMORY_INFO_TYPE(
                    self.stream.readUInt64(),
                    self.stream.readUInt64(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt64(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32())
            memoryInfoList.memory.append(memory)
        return memoryInfoList

    def _readThreadInfoList(self):
        threadInfoList = namedtuple('THREAD_INFO_LIST', [
            'sizeOfHeader',
            'sizeOfEntry',
            'numberOfEntries',
            'thread'])(
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                [])
        THREAD_INFO_TYPE = namedtuple('THREAD_INFO', [ 'threadId', 'dumpFlags', 'dumpError', 'exitStatus', 'createTime', 'exitTime', 'kernelTime', 'userTime', 'startAddress', 'affinity'])
        for i in xrange(threadInfoList.numberOfEntries):
            threadInfo = THREAD_INFO_TYPE(
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt64(),
                    self.stream.readUInt64(),
                    self.stream.readUInt64(),
                    self.stream.readUInt64(),
                    self.stream.readUInt64(),
                    self.stream.readUInt64())
            threadInfoList.thread.append(threadInfo)
        return threadInfoList

    def _readHandleOperationList(self):
        handleOperationList = namedtuple('HANDLE_OPERATION_LIST', [
            'sizeOfHeader',
            'sizeOfEntry',
            'numberOfEntries',
            'reserved',
            'handleOperation'])(
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                self.stream.readUInt32(),
                [])
        AVRF_BACKTRACE_INFORMATION_TYPE = namedtuple('AVRF_BACKTRACE_INFORMATION', ['handle', 'processId', 'threadId', 'operationType', 'spare0', 'depth', 'index', 'returnAddresses'])
        for i in xrange(handleOperationList.numberOfEntries):
            handleOperaiton = AVRF_BACKTRACE_INFORMATION_TYPE(
                    self.stream.readUInt64(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    self.stream.readUInt32(),
                    [])
            for t in xrange(32):
                handleOperaiton.returnAddresses.append(self.stream.readUInt64())
            handleOperationList.handleOperaiton.append(handleOperaiton)
        return handleOperationList

    def _readMemoryDescriptor(self):
        return (self.stream.readUInt64(),) + self._readLocationDescriptor()

    def _readLocationDescriptor(self):
        return (self.stream.readUInt32(), self.stream.readUInt32())

    def _readStringFrom(self, rva):
        self.stream.pushOffset()
        self.stream.seek(rva)
        length = self.stream.readUInt32()
        result = self.stream.read(length).decode('UTF16')
        self.stream.popOffset()
        return result

    def getRegionStartEnd(self, addr):
        for r in self._REGIONS:
            if r[0] <= addr and addr < r[1]:
                return r
        return (0,0)

    def getMemoryMap(self):
        return [('',) + x for x in self._REGIONS]

    def readMemory(self, addr, length):
        region = self.getRegionStartEnd(addr)
        if (addr + length) > region[1]:
            raise ReadError(region[1])
        offset = addr - region[0]
        return self._DATA[region[0]][offset:offset+length]

    def isAddressValid(self, addr):
        for start, end in self._REGIONS:
            if start <= addr and addr > end:
                return True
        return False

    def getEndianity(self):
        return self._ENDIANITY

    def disasm(self, addr, length=0x100, decodeType=1):
        if IS_DISASSEMBLER_FOUND:
            for opcode in distorm3.Decode(
                    addr,
                    self.readMemory(addr, length),
                    decodeType):
                print('{0:x} {1:24s} {2:s}'.format(opcode[0], opcode[3], opcode[2]))
        else:
            raise Exception("No disassembler module")

    def enumModules( self, isVerbose=False ):
        """
        Return list of tuples containg infromation about the modules loaded in memory in the form of
        (Address, module_name, module_size)
        """
        return ([(x[0], '', x[1] - x[0]) for x in self._REGIONS])

    def findModule( self, target_module, isVerbose=False ):
        target_module = target_module.lower()
        for module in self.moduleList:
            if target_module in module.moduleName.lower():
                return module.baseOfImage
        raise Exception("Can't find module %s" % target_module)

    def getModulePath( self, base ):
        if isinstance(base, str):
            base = self.findModule(base)
        for module in self.moduleList:
            if base == module.baseOfImage:
                return module.moduleName

