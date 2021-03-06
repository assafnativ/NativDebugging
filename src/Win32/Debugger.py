#
#   Debugger.py
#
#   Debugger - Win32 debugger python module
#   https://github.com/assafnativ/NativDebugging
#   Nativ.Assaf+debugging@gmail.com
#   Copyright (C) 2019  Assaf Nativ

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
from ..DebuggerBase import DebuggerBase
from .MemoryReader import MemoryReader
from .ProcessCreateAndAttach import *
from platform import python_implementation

from .BreakPoint import *
from .DllInfo import *
from .Win32Structs import *
from ..Utilities import *

# For debugging
import traceback
import sys
# For making debugger blocking free
from threading import Thread, Lock
# Arkon's disassembler
try:
    import distorm3
    IS_DISTORM_SUPPORTED = True
except ImportError as e:
    IS_DISTORM_SUPPORTED = False

# Process state
PROCESS_STATE_NO_PROCESS                    = 0
PROCESS_STATE_LOADED                        = 1
PROCESS_STATE_RUN                           = 2
PROCESS_STATE_RECOVER_FROM_BREAK_POINT      = 4 # Need to remove all break points, etc...
PROCESS_STATE_SINGLE_STEP                   = 8
PROCESS_STATE_RECOVER_FROM_TEMP_SINGLE_STEP = 16
PROCESS_STATE_RECOVER_FROM_SINGLE_STEP      = 32
PROCESS_STATE_HANDLING_DEBUGGER_EVENT       = 64

# Control commands
CTRL_CMD_NOP    = 0x00
CTRL_CMD_LOAD   = 0x01
CTRL_CMD_ATTACH = 0x02
CTRL_CMD_DETACH = 0x04
CTRL_CMD_GO     = 0x08
CTRL_CMD_EXIT   = 0x80

VALID_REGISTERS_x86 = ['dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7', 'floatsave', 'seggs', 'segfs', 'seges', 'segds', 'edi', 'esi', 'ebx', 'edx', 'ecx', 'eax', 'ebp', 'eip', 'segcs', 'eflags', 'esp', 'segss']
VALID_REGISTERS_x86_64 = ['dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7', 'FloatingPointData', 'seggs', 'segfs', 'seges', 'segds', 'rdi', 'rsi', 'rbx', 'rdx', 'rcx', 'rax', 'rbp', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'segcs', 'rflags', 'rsp', 'segss']
VALID_REGISTERS = VALID_REGISTERS_x86_64

def attach(targetProcessId):
    return Win32Debugger(target_process_id=int(targetProcessId))

def create(processName):
    return Win32Debugger(cmd_line=str(processName))

class ProcessEnded(Exception):
    pass

class Win32Debugger( DebuggerBase, MemoryReader, ProcessCreateAndAttach ):
    def __init__(self, \
            target_process_id=None, \
            cmd_line=None, \
            create_suspended=False, \
            create_info=None ):
        """
        Constructor of the Win32Debugger class.
        """

        # For talking with the control center
        self._commands         = []
        self._commandLock      = Lock()
        self._isDoneLoading    = Lock()
        # Set the commands handlers
        self._commandHandler = {}
        self._commandHandler[CTRL_CMD_NOP]       = self._nop
        self._commandHandler[CTRL_CMD_LOAD]      = self._load
        self._commandHandler[CTRL_CMD_ATTACH]    = self._attach
        self._commandHandler[CTRL_CMD_DETACH]    = self._detach
        self._commandHandler[CTRL_CMD_GO]        = self._run
        self._commandHandler[CTRL_CMD_EXIT]      = self._nop

        # Create the control thread
        self._controlThread = Thread( target=self._mainControl, name="DebuggerControl" )

        self._lastDebugEvent = DEBUG_EVENT()
        self.context = CONTEXT_x86_64()

        self._state = PROCESS_STATE_NO_PROCESS
        self._processId = 0
        self._isDirty = False
        self.solveAddr = None
        self.breakOnModuleLoad = False
        self.breakOnModuleUnload = False

        if '32 bit' in python_implementation():
            self._isWin64 = False
            self._contextType = win32con.CONTEXT_FULL | win32con.CONTEXT_i386
        else:
            self._isWin64 = True
            self._contextType = win32con.CONTEXT_FULL | win32con.CONTEXT_AMD64

        self._controlThread.start()

        # Get myself some debugging privileges
        adjustDebugPrivileges()

        if None == target_process_id:
            self.load(cmd_line, create_suspended, create_info)
        else:
            # Attach to process
            self.attach(target_process_id)

        DebuggerBase.__init__(self)

    def __del__( self ):
        """
        Destructor of the Win32Debugger class
        """
        # Kill the control center
        self._setCommand( CTRL_CMD_EXIT )

    def _setCommand( self, command, params=None ):
        """
        Send a command to the main control thread.
        """
        with self._commandLock:
            # Now we can safely set the command and its' params
            self._commands.append((command, params))

    def _nop( self ):
        pass

    def _mainControl( self ):
        """
        This function handles commands sent from user and executes the right handler.
        It must be done this way to make the debugger none blocking (Coz the win32
        debug API must be used from the debugging thread).
        """

        cmd = CTRL_CMD_NOP
        while( CTRL_CMD_EXIT != cmd ):
            with self._commandLock:
                if 0 < len(self._commands):
                    cmd, params = self._commands.pop()
                else:
                    cmd = CTRL_CMD_NOP
                    params = []

            # Handle the new command
            if( CTRL_CMD_NOP != cmd ):
                # For debug
                try:
                    self._commandHandler[cmd]( *params )
                except:
                    traceback.print_exc( sys.exc_info )

            if CTRL_CMD_DETACH == cmd:
                break

    def _clearAllForFirstTime(self):
        # Clear all
        self._dlls = []
        self._breakPoints = []
        self._pause = False
        self._isExceptionHandled = True
        self._returnToUser = False
        self._state = PROCESS_STATE_LOADED
        self._areBreakPointsInstalled = True
        self._thread_dictionary = {}

    def _create(self, \
            cmd_line=None, \
            create_suspended=False, \
            create_info=None ):

        MemoryReader.__init__(self,
                target_process_id = None,
                target_open_handle = None,
                cmd_line = cmd_line,
                create_suspended = create_suspended,
                create_info = create_info)


        self._clearAllForFirstTime()
        self._thread_dictionary = { self._currentThreadId : self._currentThread }

    def _load( self, command_line, create_suspended=False, create_info=None ):
        """
        Load a new executable.
        """

        if None == create_info:
            create_info = {'CREATION_FLAGS' : win32con.NORMAL_PRIORITY_CLASS}
        create_info['CREATION_FLAGS'] = create_info.get('CREATION_FLAGS', 0) | win32con.DEBUG_PROCESS

        ProcessCreateAndAttach.__init__(self,
                                        None,
                                        None,
                                        command_line,
                                        create_suspended,
                                        create_info )

        self._clearAllForFirstTime()
        self._thread_dictionary = {self._currentThreadId : self._currentThread}

        MemoryReader.__init__(self, self._processId, self._process)

        # Make one go, to stop after program is loaded
        self._run()

    def load( self, command_line, create_suspended=False, create_info=None ):
        # Wait till loding is over, we know it's over when the lock is free.
        # TBD: need to think of a better way to do it...
        self._setCommand( CTRL_CMD_LOAD, (command_line, create_suspended, create_info) )
        while( not self._isDoneLoading.locked() ):
            pass

    def _attach( self, processId ):
        """
        Attach to running process
        """

        DebugActiveProcess( processId )

        # Setup
        self._processId = processId
        self._clearAllForFirstTime()

    def _detach( self ):
        """
        Detach from debuged process
        """

        if (0 != self._processId):
            DebugActiveProcessStop( self._processId )
            self._run()
        else:
            print("No process to detach from")

        # Clear all
        self._processId = 0
        self._clearAllForFirstTime()
        self._state = PROCESS_STATE_NO_PROCESS

    def attach( self, processId ):
        self._setCommand( CTRL_CMD_ATTACH, (processId,) )
        # Wait till loding is over, we know it's over when the lock is free.
        # TBD: need to think of a better way to do it...
        while( not self._commandLock.locked() ):
            pass
        while( self._commandLock.locked() ):
            pass

    def detach( self ):
        self._uninstallAllBreakPoints()
        self._setCommand( CTRL_CMD_DETACH, () )
        del self

    def pause( self ):
        print('Pause')
        self._returnToUser = True

    def _runBlocking( self ):
        if( True == self._pause ):
            if( True == self._isExceptionHandled ):
                ContinueDebugEvent(
                        self._lastDebugEvent.dwProcessId,
                        self._lastDebugEvent.dwThreadId,
                        win32con.DBG_CONTINUE )
            else:
                #print 'Debug exception was not handled by us, pass it to the program'
                ContinueDebugEvent(
                        self._lastDebugEvent.dwProcessId,
                        self._lastDebugEvent.dwThreadId,
                        win32con.DBG_EXCEPTION_NOT_HANDLED )

        self._pause = False
        WaitForDebugEvent(byref(self._lastDebugEvent), win32con.INFINITE)
        self._pause = True

    def getThreadsList( self ):
        return self._thread_dictionary.copy()

    def getCurrentContext( self ):
        self.context.ContextFlags = self._contextType
        GetThreadContext( self._currentThread, byref(self.context) )

    def setCurrentContext( self ):
        self.context.ContextFlags = self._contextType
        SetThreadContext( self._currentThread, byref(self.context) )

    def _run( self ):
        """
        Same as run only blocking
        """
        self._makeProcessReadyToRun()
        self._debugerMainLoop()

    def run( self ):
        """
        Run the process to the next event.
        """
        self._setCommand( CTRL_CMD_GO, () )

    def isProcessAlive( self ):
        return PROCESS_STATE_NO_PROCESS != self._state

    def isProcessRunning( self ):
        return PROCESS_STATE_RUN == self._state

    def _debugerMainLoop( self ):
        """
        Run until break worth thee event
        used from go command
        """

        try:
            while True:
                # Run
                self._runBlocking()
                # Handle the event
                event_code = self._lastDebugEvent.dwDebugEventCode
                if( event_code == win32con.EXCEPTION_DEBUG_EVENT ):
                    # First we get the current context
                    self._currentThread = self._thread_dictionary[self._lastDebugEvent.dwThreadId]
                    self.getCurrentContext()

                    exception_info = self._lastDebugEvent.u.Exception
                    exception_code = exception_info.ExceptionRecord.ExceptionCode
                    self.lastExceptionCode = exception_code

                    # Exception considered unhandled until proved otherwise
                    self._isExceptionHandled = False

                    if( exception_code == win32con.EXCEPTION_BREAKPOINT ):
                        break_point_index = self._onBreakPoint()
                        if( True == self._returnToUser ):
                            # print 'Returning to user'
                            self._returnToUser = False
                            self._isExceptionHandled = True
                            return( break_point_index )
                        elif( -1 == break_point_index ):
                            return( -1 )
                        else:
                            self._isExceptionHandled = True
                            self._makeProcessReadyToRun()
                    elif( exception_code == win32con.EXCEPTION_ACCESS_VIOLATION ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_ARRAY_BOUNDS_EXCEEDED ):
                        pass


                    elif( exception_code == win32con.EXCEPTION_DATATYPE_MISALIGNMENT ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_FLT_DENORMAL_OPERAND ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_FLT_DIVIDE_BY_ZERO ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_FLT_INEXACT_RESULT ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_FLT_INVALID_OPERATION ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_FLT_OVERFLOW ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_FLT_STACK_CHECK ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_FLT_UNDERFLOW ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_ILLEGAL_INSTRUCTION ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_IN_PAGE_ERROR ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_INT_DIVIDE_BY_ZERO ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_INT_OVERFLOW ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_INVALID_DISPOSITION ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_NONCONTINUABLE_EXCEPTION ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_PRIV_INSTRUCTION ):
                        pass
                    elif( exception_code == win32con.EXCEPTION_SINGLE_STEP ):
                        self._isExceptionHandled = True
                        # Need to recover from break point next run...
                        if( self._state == PROCESS_STATE_RECOVER_FROM_TEMP_SINGLE_STEP ):
                            self._makeProcessReadyToRun()
                            continue
                        self._state = PROCESS_STATE_RECOVER_FROM_SINGLE_STEP
                        print("Single step")
                        return( -1 )

                    elif( exception_code == win32con.EXCEPTION_STACK_OVERFLOW ):
                        pass
                    elif( exception_code == win32con.DBG_CONTROL_C ):
                        pass
                    elif( exception_code == win32con.DBG_CONTROL_BREAK ):
                        pass
                    else:
                        #print "Unknown exception type! (%X)" % long(exception_code)
                        pass

                    if( 0 == exception_info.dwFirstChance ):
                        print("None first chance exception not handled")
                        return( -1 )

                elif( event_code == win32con.CREATE_THREAD_DEBUG_EVENT ):
                    self._currentThread    = self._lastDebugEvent.u.CreateThread.hThread
                    self._thread_dictionary[self._lastDebugEvent.dwThreadId] = self._currentThread
                    #print "Thread created (Id: %x)" % self._currentThread

                elif( event_code == win32con.CREATE_PROCESS_DEBUG_EVENT ):
                    # Probably raised due to attach
                    process_info = self._lastDebugEvent.u.CreateProcessInfo

                    self._process          = process_info.hProcess
                    self._currentThread    = process_info.hThread
                    self._thread_dictionary[self._lastDebugEvent.dwThreadId] = self._currentThread
                    MemoryReader.__init__(self, self._processId, self._process)

                    # Get the module file name
                    module_name = ''
                    if (process_info.lpImageName):
                        module_name = self.readString(process_info.lpImageName, isUnicode=process_info.fUnicode)
                    # Save its info
                    self._dlls.append( DllInfo(
                                            process_info.hFile,
                                            process_info.lpBaseOfImage,
                                            process_info.dwDebugInfoFileOffset,
                                            process_info.lpImageName,
                                            module_name) )

                    self._isDoneLoading.acquire()

                elif( event_code == win32con.EXIT_THREAD_DEBUG_EVENT ):
                    # Remove the dyeing thread from the thread list
                    del( self._thread_dictionary[self._lastDebugEvent.dwThreadId] )
                elif( event_code == win32con.EXIT_PROCESS_DEBUG_EVENT ):
                    self._state = PROCESS_STATE_NO_PROCESS
                    return
                elif( event_code == win32con.LOAD_DLL_DEBUG_EVENT ):
                    newDll = self._lastDebugEvent.u.LoadDll
                    # First get the dll file name
                    module_name = c_wchar_p('a' * 0x1000)
                    GetFinalPathNameByHandle(
                            newDll.hFile,
                            module_name,
                            0x1000,
                            0)
                    dll_info = DllInfo(
                            newDll.hFile,
                            newDll.lpBaseOfDll,
                            newDll.dwDebugInfoFileOffset,
                            newDll.lpImageName,
                            module_name.value )

                    self._dlls.append( dll_info )
                    if self.breakOnModuleLoad:
                        self._state = PROCESS_STATE_HANDLING_DEBUGGER_EVENT
                        return -1

                elif( event_code == win32con.UNLOAD_DLL_DEBUG_EVENT ):
                    base_address = self._lastDebugEvent.u.UnloadDll.lpBaseOfDll
                    # Remove the unloaded dll from the dlls list
                    for dll in self._dlls:
                        if( dll.baseAddress == base_address ):
                            self._dlls.remove( dll )
                            break
                    if self.breakOnModuleUnload:
                        self._state = PROCESS_STATE_HANDLING_DEBUGGER_EVENT
                        return -1

                elif( event_code == win32con.OUTPUT_DEBUG_STRING_EVENT ):
                    info = self._lastDebugEvent.u.DebugString
                    debugString = self.readString(info.lpDebugStringData, info.nDebugStringLength, isUnicode=info.fUnicode)
                    print("Output string %s" % debugString)
                elif( event_code == win32con.RIP_EVENT ):
                    print("RIP")
                else:
                    print("Unknown debug event! {0:d}".format(event_code))

                if True == self._isDirty:
                    FlushInstructionCache(self._process, None, 0)
                    self._isDirty = False
        except ProcessEnded as _:
            print("Target died!")
            return
        except:
            # The user breakpoint raised an exception...
            # Print out the traceback, n stop execution
            traceback.print_exc()
            self.pause()

    def disassemble( self, address = None, lines = None ):
        """
        Display unassembley (disassembly) of memory
        Gets:
            unsigned long   address
            unsigned long   lines
        """
        if not IS_DISTORM_SUPPORTED:
            raise Exception("Distrom not found, please install the distorm3 module")

        if( None == address ):
            self.getCurrentContext()
            address = self.context.rip
        if( None != lines ):
            bytes_to_read = [lines * 8, 100][lines * 8 < 100]   # Thats should be enough, and if not who cares.
        else:
            bytes_to_read = 100     # That's a magic number

        # First read the relavent data.
        # Remove all break points, so we wont read them
        self._uninstallAllBreakPoints()
        data = self.readMemory( address, bytes_to_read )
        self._reinstallAllBreakPoints()

        # Now disassemble with distorm.
        data = distorm3.Decode( address, data, distorm3.Decode32Bits )

        # Print the result
        data[:lines]
        for opcode in data:
            print("0x{0:08X} ({1:02X}) {2:<20s} {3:s}".format(opcode[0], opcode[1], opcode[3], opcode[2]))

        return

    def u( self, address = None, lines = None ):
        """ Wrapper for the disassemble command """
        self.disassemble(address, lines)

    def breakpointSet( self, address, proc = pause ):
        """
        Set a break point on execution.
        Gets:
            unsigned long   address
            proc            Python fuction to excute on every break
        Return:
            int - The index number of the break point.
        """
        # Check that we don't have a breakpoint already
        for bp in self._breakPoints:
            if( bp.address == address ):
                print('Already a breakpoint')
                return -1
        # Save the original byte
        original_byte = self.readUInt8( address )
        if( BREAK_POINT_BYTE == original_byte ):
            print('Already a breakpoint - Adding it to the list')
        # Write the int3 opcode
        self.deprotectAndWriteUInt8( address, BREAK_POINT_BYTE )
        self._breakPoints.append( BreakPoint(address, 1, original_byte, proc) )
        return( len(self._breakPoints) - 1 )

    def breakpointsList( self ):
        """
        List all break points.
        """
        result = ""
        for break_point in self._breakPoints:
            result += str( self._breakPoints.index( break_point ) )
            if( BREAK_POINT_ACTIVE | break_point.state ):
                # Breakpoint is active.
                result += "   "
            elif( not BREAK_POINT_ACTIVE | break_point.state ):
                # Breakpoint is not active.
                reuslt += " * "
            result += hex( break_point.address )
            result += '\n'
        return result

    def _breakpointRemove( self, break_point ):
        """
        Makes the actually remove of the breakpoint, in a safly way.
        """
        if( (BREAK_POINT_ACTIVE & break_point.state) and (self._state != PROCESS_STATE_RECOVER_FROM_BREAK_POINT) ):
            current_byte = self.readUInt8( break_point.address )
            if( current_byte != break_point.original_byte ):
                raise Exception('Somone overwritten the breakpoint!')
            self.deprotectAndWriteUInt8( break_point.address, break_point.original_byte )

    def breakpointRemove( self, index ):
        """
        Remove a break point.
        Gets:
            int index
            or
            char '*' to remove all breakpoints
        """
        if( '*' == index ):
            # Remove all breakpoints
            for break_point in self._breakPoints:
                self._breakpointRemove( break_point )
            self._breakPoints = []
            return

        # Remove a single breakpoint
        break_point = self._breakPoints[index]
        self._breakpointRemove( break_point )
        self._breakPoints.remove( break_point )

    def _breakpointDisable( self, break_point ):
        if( not (BREAK_POINT_ACTIVE & break_point.state) ):
            #print("Break point is allread disabled")
            return
        if( True == self._areBreakPointsInstalled ):
            if( BREAK_POINT_BYTE != self.readUInt8( break_point.address ) ):
                print("Program state = {0:s}".format(str(self._state)))
                raise Exception( 'Breakpoint had been overwrite by somthing' )
            self.deprotectAndWriteUInt8( break_point.address, break_point.original_byte )
        break_point.state &= ~BREAK_POINT_ACTIVE

    def breakpointDisable( self, index ):
        """
        Disable a break point.
        Gets:
            int index
            or
            char '*' to remove all breakpoints
        """
        if( '*' == index ):
            # Disable all breakpoints
            for break_point in self._breakPoints:
                if( BREAK_POINT_ACTIVE | break_point.state ):
                    self._breakpointDisable( break_point )
        else:
            # Disable a single breakpoint
            break_point = self._breakPoints[index]
            self._breakpointDisable( break_point )

    def _breakpointEnable( self, break_point ):
        if( BREAK_POINT_ACTIVE & break_point.state ):
            #print("Break point is allread enabled")
            return
        if( True == self._areBreakPointsInstalled ):
            self.deprotectAndWriteUInt8( break_point.address, BREAK_POINT_BYTE )
        break_point.state |= BREAK_POINT_ACTIVE

    def breakpointEnable( self, index ):
        """
        TODO: handle pause state
        Enable a break point.
        Gets:
            int index
        """
        if( '*' == index ):
            # Disable all breakpoints
            for break_point in self._breakPoints:
                if( not BREAK_POINT_ACTIVE | break_point.state ):
                    self._breakpointEnable( break_point )
        else:
            # Enbale a single breakpoint
            break_point = self._breakPoints[index]
            self._breakpointEnable( break_point )

    def _contextShow( self ):
        """
        Returns the current registers and machine state.
        Returns:
            context
        """
        context = self.context
        #text_x86 = 'EAX {0:08x}\tECX {1:08x}\tEDX {2:08x}\tEBX {3:08x}\nEDI {4:08x}\tESI {5:08x}\tEBP {6:08x}\tEIP {7:08x}\nSegCs {8:08x}\tEFlags {9:08x}\tESP {10:08x}\tSegSs {11:08x}\n'
        #text_x86 = text_x86.format(context.eax, context.ecx, context.edx, context.ebx, context.edi, context.esi, context.ebp, context.eip, context.segcs, context.eflags, context.esp, context.segss)
        text_x86_64 = 'rax {0:016x}\trcx {1:016x}\trdx {2:016x}\trbx {3:016x}\nrdi {4:016x}\trsi {5:016x}\trbp {6:016x}\trip {7:016x}\n r8={8:016x}\t r9={9:016x}\tr10={10:016x}\nr11={11:016x}\tr12={12:016x}\tr13={13:016x}\nr14={14:016x}\tr15={15:016x}\nsegcs {16:016x}\trflags {17:016x}\trsp {18:016x}\tsegss {19:016x}\n'
        text_x86_64 = text_x86_64.format(context.rax, context.rcx, context.rdx, context.rbx, context.rdi, context.rsi, context.rbp, context.rip, context.r8, context.r9, context.r10, context.r11, context.r12, context.r13, context.r14, context.r15, context.segcs, context.rflags, context.rsp, context.segss)
        return text_x86_64

    def contextShow( self ):
        """
        Prints the current registers and machine state.
        Returns:
            context
        """
        print(self._contextShow)

    def trace( self ):
        """
        Trace one opcode
        """
        #self._makeProcessReadyToRun( )
        self._state = PROCESS_STATE_SINGLE_STEP
        self.context.eflags |= 0x100
        self.setCurrentContext( )
        self._uninstallAllBreakPoints( )
        self._run()

    def t(self):
        """
        Wrapper for trace command
        """
        self.trace()

    def hideDebugger( self ):
        """
        Rewrites the debugger flag in the PEB

        TBD: not working yet
        """
        self.deprotectAndWriteUInt8( self.readUInt32(0x7ffde030) + 2, 0 )

    def _uninstallAllBreakPoints( self ):
        """
        Uninstall all break points to handle a break.
        """
        # print 'DEBUG: Uninstall'
        for break_point in self._breakPoints:
            if( BREAK_POINT_ACTIVE | break_point.state ):
                self.deprotectAndWriteUInt8( break_point.address, break_point.original_byte )
            break_point.state |= BREAK_POINT_HIDE
        self._areBreakPointsInstalled = False

    def _reinstallAllBreakPoints( self ):
        """
        Reinstall all break points after handling a break.
        """
        # print 'DEBUG: Reinstall'
        self._areBreakPointsInstalled = True
        for break_point in self._breakPoints:
            if( BREAK_POINT_ACTIVE | break_point.state ):
                self.deprotectAndWriteUInt8( break_point.address, BREAK_POINT_BYTE )
            break_point.state &= ~BREAK_POINT_HIDE

    def _onBreakPoint( self ):
        if( PROCESS_STATE_LOADED == self._state ):
            # First break point.
            self._returnToUser = False
            self._isExceptionHandled = True
            self._state = PROCESS_STATE_RUN
            return -1
        elif( PROCESS_STATE_RUN == self._state ):
            # The process was in a middel of normal running
            self._state = PROCESS_STATE_RECOVER_FROM_BREAK_POINT
        # print "Break point"
        rip = self.context.rip - 1
        self._uninstallAllBreakPoints()
        for break_point in self._breakPoints:
            if( break_point.address == rip ):
                # This is one of the user break points
                self.context.rip -= 1
                break_point.proc( self )
                return self._breakPoints.index( break_point )
        return -1

    def _makeProcessReadyToRun( self ):
        if( PROCESS_STATE_NO_PROCESS == self._state ):
            raise ProcessEnded(self._processId)
        elif( PROCESS_STATE_RUN == self._state ):
            # Nothing to be done...
            return
        elif( PROCESS_STATE_LOADED == self._state ):
            # Nothing to be done...
            return
        elif( PROCESS_STATE_RECOVER_FROM_BREAK_POINT == self._state ):
            self._state = PROCESS_STATE_RECOVER_FROM_TEMP_SINGLE_STEP
            self.context.eflags |= 0x100
            self.setCurrentContext()
            return
        elif( self._state in [
                    PROCESS_STATE_RECOVER_FROM_TEMP_SINGLE_STEP,
                    PROCESS_STATE_RECOVER_FROM_SINGLE_STEP,
                    PROCESS_STATE_HANDLING_DEBUGGER_EVENT]):
            self._state = PROCESS_STATE_RUN
            self._reinstallAllBreakPoints()
            return
        elif( PROCESS_STATE_SINGLE_STEP == self._state ):
            self._state = PROCESS_STATE_RUN
            return
        else:
            print("Unknown state")
            raise Exception

    def enumModules( self, isVerbose=False ):
        for dllInfo in self._dlls:
            module_name = dllInfo.name
            module_info = MODULEINFO(0)
            GetModuleInformation( self._process, module_name, byref(module_info), sizeof(module_info) )
            module_base = module_info.lpBaseOfDll
            module_size = module_info.SizeOfImage
            if isVerbose:
                print("Module: (0x{0:x}) {1:s} of size (0x{2:x})".format(module_base, module_name, module_size))
            yield (module_base, module_name, module_size)

    def getModuleBase( self, moduleName ):
        moduleNameLower = moduleName.lower()
        for dllInfo in self._dlls:
            if moduleNameLower == os.path.basename(dllInfo.name).lower():
                return dllInfo.baseAddress
        return -1

    def findProcAddress(self, dllName, target):
        """
        Search for exported function in the remote process.
        """
        base = self.getModuleBase(dllName)
        if -1 == base:
            raise Exception("Cant' find base of %s" % dllName)
        return self.findProcAddressFromModuleBase(base, target)

