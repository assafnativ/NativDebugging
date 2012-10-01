from NativDebugging.Win32 import MemoryReader
process_id = MemoryReader.findProcessId('winm')[0][1]
m = MemoryReader.attach(process_id)
base = m.findModule('winmine')
m.dd(base)
m.db(base)
