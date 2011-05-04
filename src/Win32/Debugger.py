#
#   win32Debugger.py
#
#   win32Debugger - Win32 debugger python module
#   https://svn3.xp-dev.com/svn/nativDebugging/
#   Nativ.Assaf+debugging@gmail.com
#   Copyright (C) 2011  Assaf Nativ

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
from ..Interfaces import DebuggerInterface
from .ProcessInspector import ProcessInspector

from .BreakPoint import *
from .DllInfo import *
from .Win32Structs import *
from .Win32Utile import *
from ..Utile import *
    
# For debugging
import traceback
import sys
# For making debugger blocking free
from thread import *
# Arkon's disassembler
import distorm3

# Consts
DEBUG_MODE  = False

# Process state
PROCESS_STATE_NO_PROCESS                    = 0
PROCESS_STATE_LOADED                        = 1
PROCESS_STATE_RUN                           = 2
PROCESS_STATE_RECOVER_FROM_BREAK_POINT      = 4 # Need to remove all break points, etc...
PROCESS_STATE_SINGLE_STEP                   = 8
PROCESS_STATE_RECOVER_FROM_TEMP_SINGLE_STEP = 16
PROCESS_STATE_RECOVER_FROM_SINGLE_STEP      = 32

# Control commands
CTRL_CMD_NOP    = 0x00
CTRL_CMD_LOAD   = 0x01
CTRL_CMD_ATTACH = 0x02
CTRL_CMD_DETACH = 0x04
CTRL_CMD_GO     = 0x08
CTRL_CMD_EXIT   = 0x80

VALID_REGISTERS = ['dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7', 'floatsave', 'seggs', 'segfs', 'seges', 'segds', 'edi', 'esi', 'ebx', 'edx', 'ecx', 'eax', 'ebp', 'eip', 'segcs', 'eflags', 'esp', 'segss']

def attach(targetProcessId):
    return Win32Debugger(int(targetProcessId))

def create(processName):
    return Win32Debugger(str(processName))

class Win32Debugger( DebuggerInterface, ProcessInspector ):
    def __init__(self, process = None):
        """ 
        Constructor of the Win32Debugger class.
        """
        
        # For talking with the control center
        self._command          = CTRL_CMD_NOP
        self._commandLock      = allocate_lock()
        self._commandParams    = None
        self._isDoneLoading    = allocate_lock()
        # Set the commands handlers
        self._commandHandler = {}
        self._commandHandler[ CTRL_CMD_NOP ]       = self._nop
        self._commandHandler[ CTRL_CMD_LOAD ]      = self._load
        self._commandHandler[ CTRL_CMD_ATTACH ]    = self._attach
        self._commandHandler[ CTRL_CMD_DETACH ]    = self._detach
        self._commandHandler[ CTRL_CMD_GO ]        = self._g
        self._commandHandler[ CTRL_CMD_EXIT ]      = self._nop

        # Create the control thread
        self._controlThread = start_new_thread( self._mainControl, () )
        
        self._lastDebugEvent = DEBUG_EVENT()
        # A temp thread would use us to make go command not blocking
        self._tempThread = None
        self.context = CONTEXT()

        self._state = PROCESS_STATE_NO_PROCESS
        self._processId = 0
        self._isDirty = False
        self.solveAddr = None
 
        # Get myself debugging privileges
        adjustDebugPrivileges()

        if( str == type(process) ):
            # Create the process
            self.load(process)
        elif( int == type(process) or long == type(process) ):
            # Attach to process
            self.attach(process)
        else:
            raise Exception("Don't know how to debug this")
        
    def __del__( self ):
        """
        Destructor of the Win32Debugger class
        """
        # Kill the control center
        self._setCommand( CTRL_CMD_EXIT )
        
    def _setCommand( self, command, params ):
        """
        Send a command to the main control thread.
        """
        # Mutex
        self._commandLock.acquire()
        
        # Now we can safly set the command and its' params
        self._command = command
        self._commandParams = params
        
        # Free Mutex
        self._commandLock.release()

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
            # Mutex
            self._commandLock.acquire()
            
            cmd = self._command

            # Handle the new command
            if( CTRL_CMD_NOP != cmd ):
                # For debug 
                if( True == DEBUG_MODE ):
                    print cmd
                    print self._commandParams
                try:
                    self._commandHandler[ cmd ]( *self._commandParams )
                except:
                    traceback.print_exc( sys.exc_info )
            # Make sure we wont handle it again
            self._command = CTRL_CMD_NOP
            
            # Free Mutex
            self._commandLock.release()

    def _load( self, command_line ):
        """
        Load a new executable.
        """

        process_startup_info                    = STARTUPINFO()
        process_startup_info.cp                 = sizeof( STARTUPINFO )
        process_startup_info.lpReserved         = pchar_NULL
        process_startup_info.lpDesktop          = pchar_NULL
        process_startup_info.lpTitle            = pchar_NULL 
        process_startup_info.dwX                = win32con.CW_USEDEFAULT
        process_startup_info.dwY                = win32con.CW_USEDEFAULT
        process_startup_info.dwXSize            = win32con.STARTF_USESIZE
        process_startup_info.dwYSize            = win32con.STARTF_USESIZE
        process_startup_info.dwXCountChars      = 0
        process_startup_info.dwYCountChars      = 0
        process_startup_info.dwFillAttribute    = 0

        _processInfo = PROCESS_INFORMATION()

        CreateProcess( \
            pchar_NULL,
            command_line,
            void_NULL,
            void_NULL,
            TRUE,
            win32con.DEBUG_PROCESS | win32con.NORMAL_PRIORITY_CLASS,
            void_NULL,
            pchar_NULL,
            byref( process_startup_info ),
            byref( _processInfo ) )
        
        # Set current state
        self._process         = _processInfo.hProcess
        self._currentThread   = _processInfo.hThread
        self._processId       = _processInfo.dwProcessId
        self._currentThreadId = _processInfo.dwThreadId
        print "Process (id %d, handle %08x) was created with main thread (id %d, handle %08x)" % \
                (self._processId, self._process, self._currentThreadId, self._currentThread)
        
        # Clear all
        self._dlls = []
        self._breakPoints = []
        self._pause = False
        self._isExceptionHandled = True
        self._returnToUser = False
        self._state = PROCESS_STATE_LOADED
        self._areBreakPointsInstalled = True
        self._thread_dictionary = { self._currentThread : _processInfo.dwThreadId }

        # Make one go, to stop after program is loaded
        self._g()
        
        # Done loading
        self._isDoneLoading.acquire()

    def load( self, command_line ):
        self._setCommand( CTRL_CMD_LOAD, (command_line,) )
        # Wait till loding is over, we know it's over when the lock is free.
        # TBD: need to think of a better way to do it...
        while( not self._isDoneLoading.locked() ):
            pass
        
    def _attach( self, processId ):
        """
        Attach to running process
        """

        DebugActiveProcess( processId )
        
        # Clear all
        self._processId = processId
        self._breakPoints = []
        self._dlls = []
        self._pause = False
        self._isExceptionHandled = True
        self._returnToUser = False
        self._state = PROCESS_STATE_LOADED
        self._areBreakPointsInstalled = True
        self._thread_dictionary = {}

    def _detach( self ):
        """
        Detach from debuged process
        """

        if (0 != self._process_id):
            DebugActiveProcessStop( self._process_id )
        else:
            print "No process to detach from"

        # Clear all
        self._process_id = 0
        self._breakPoints = []
        self._dlls = []
        self._pause = False
        self._isExceptionHandled = True
        self._returnToUser = False
        self._state = PROCESS_STATE_LOADED
        self._areBreakPointsInstalled = True
        self._thread_dictionary = {}

    def attach( self, process_id ):
        self._setCommand( CTRL_CMD_ATTACH, (process_id,) )
        # Wait till loding is over, we know it's over when the lock is free.
        # TBD: need to think of a better way to do it...
        while( not self._commandLock.locked() ):
            pass
        while( self._commandLock.locked() ):
            pass
        
    def detach( self ):
        self._setCommand( CTRL_CMD_DETACH, () )
        del self

    def pause( self ):
        print 'Pause'
        self._returnToUser = True

    def _run( self ):
        
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

        WaitForDebugEvent( byref( self._lastDebugEvent ), win32con.INFINITE )
        #exception_info = self._lastDebugEvent.u.Exception
        #exception_code = exception_info.ExceptionRecord.ExceptionCode
        #print 'Got new debug event', self._lastDebugEvent.dwDebugEventCode, exception_info.dwFirstChance, exception_code, self._pause

        self._pause = True
            
        
    def getThreadsList( self ):
        return self._thread_dictionary.copy()

    def getCurrentContext( self ):
        self.context.ContextFlags = win32con.CONTEXT_FULL | win32con.CONTEXT_i386
        GetThreadContext( self._currentThread, byref( self.context ) )
    
    def setCurrentContext( self ):
        # print 'DEBUG: Setting current context EIP = ', hex(self.context.eip )
        self.context.ContextFlags = win32con.CONTEXT_FULL | win32con.CONTEXT_i386
        SetThreadContext( self._currentThread, byref( self.context ) )

###     def __getattr__( self, name ):
###         regname = name.lower()
###         if( regname not in VALID_REGISTERS ):
###             if( name in self.__dict__ ):
###                 return self.__dict__[name]
###             raise AttributeError, name
###         self.getCurrentContext()
###         # I really don't like this way of accessing a variable, but thats do the job.
###         return eval( 'self.context.' + regname )
### 
###     def __setattr__( self, name, value ):
###         regname = name.lower()
###         if( regname not in VALID_REGISTERS ):
###             self.__dict__[ name ] = value
###             return
###         self.getCurrentContext()
###         # I really don't like this way of accessing a variable, but thats do the job.
###         exec( 'self.context.' + regname + '=' + str(value) )
###         self.setCurrentContext()
        
    def _g( self ):
        """
        Same as g only blocking
        """
        self._makeProcessReadyToRun()

        self._debugerMainLoop()

    def g( self ):
        """
        Run the process to the next event.
        """
        self._setCommand( CTRL_CMD_GO, () )
            
    def _debugerMainLoop( self ):
        """
        Run until break worth thee event
        used from go command
        """
        
        while True:
            # Run
            self._run()
            # Handle the event
            event_code = self._lastDebugEvent.dwDebugEventCode
            if( event_code == win32con.EXCEPTION_DEBUG_EVENT ):
                # First we get the current context
                self._currentThread = self._thread_dictionary[ self._lastDebugEvent.dwThreadId ]
                self.getCurrentContext()

                exception_info = self._lastDebugEvent.u.Exception
                exception_code = exception_info.ExceptionRecord.ExceptionCode
                # print "DEBUG: Exception event ", exception_code, 'EIP = ', hex(self.context.eip)
                
                # Exception considered unhandled until proved otherwise
                self._isExceptionHandled = False
                
                if( exception_code == win32con.EXCEPTION_ACCESS_VIOLATION ):
                    pass
                elif( exception_code == win32con.EXCEPTION_ARRAY_BOUNDS_EXCEEDED ):
                    pass
                elif( exception_code == win32con.EXCEPTION_BREAKPOINT ):
                    if( PROCESS_STATE_LOADED == self._state ):
                        self._state = PROCESS_STATE_RECOVER_FROM_BREAK_POINT
                        return( -1 )
                    break_point_index = self._onBreakPoint()
                    if( True == self._returnToUser ):
                        # print 'Returning to user'
                        self._returnToUser = False
                        self._isExceptionHandled = True
                        return( break_point_index )
                    elif( -1 == break_point_index ):
                        # print 'Unknown break point'
                        # return( -1 )
                        pass
                    else:
                        self._isExceptionHandled = True
                        self._makeProcessReadyToRun()

                    
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
                    print "Single step"
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
                    print "None first chance exception not handled"
                    return( -1 )
 
            elif( event_code == win32con.CREATE_THREAD_DEBUG_EVENT ):
                self._currentThread    = self._lastDebugEvent.u.CreateThread.hThread
                self._thread_dictionary[ self._lastDebugEvent.dwThreadId ] = self._currentThread
                #print "Thread created (Id: %x)" % self._currentThread
                
            elif( event_code == win32con.CREATE_PROCESS_DEBUG_EVENT ):
                # Probebly raised due to attach

                process_info = self._lastDebugEvent.u.CreateProcessInfo

                self._process           = process_info.hProcess
                self._currentThread    = process_info.hThread
                self._thread_dictionary[ self._lastDebugEvent.dwThreadId ] = self._currentThread

                # Get the module file name
                module_name = ''
                if( 0 != process_info.lpImageName ):
                    if( 0 == process_info.fUnicode ):
                        try:
                            module_name = self.readString( process_info.lpImageName )
                        except:
                            pass
                    else:
                        try:
                            module_name = self.readUnicodeString( process_info.lpImageName )
                        except:
                            pass
                        module_name = module_name.replace( '\x00', '' )
                
                # Save its info
                self._dlls.append( DllInfo(
                                        process_info.hFile,
                                        process_info.lpBaseOfImage,
                                        process_info.dwDebugInfoFileOffset,
                                        process_info.lpImageName,
                                        process_info.fUnicode,
                                        module_name) )
                
                print "Create Process", module_name

            elif( event_code == win32con.EXIT_THREAD_DEBUG_EVENT ):
                # Remove the dyeing thread from the thread list
                del( self._thread_dictionary[ self._lastDebugEvent.dwThreadId ] )
                #print "Exit thread"
            elif( event_code == win32con.EXIT_PROCESS_DEBUG_EVENT ):
                print "Exit process"
                self._state = PROCESS_STATE_NO_PROCESS
                return
            elif( event_code == win32con.LOAD_DLL_DEBUG_EVENT ):
                new_dll = self._lastDebugEvent.u.LoadDll
                # First get the dll file name
                name = ''
                if( 0 != new_dll.lpImageName ):
                    if( 0 == new_dll.fUnicode ):
                        try:
                            name = self.readString( new_dll.lpImageName )
                        except:
                            pass
                    else:
                        try:
                            name = self.readUnicodeString( new_dll.lpImageName )
                        except:
                            pass
                        name = name.replace( '\x00', '' )
                    #print '%s is now loaded' % name
                dll_info = DllInfo(
                        new_dll.hFile,
                        new_dll.lpBaseOfDll,
                        new_dll.dwDebugInfoFileOffset,
                        new_dll.lpImageName,
                        new_dll.fUnicode,
                        name )

                self._dlls.append( dll_info )

            elif( event_code == win32con.UNLOAD_DLL_DEBUG_EVENT ):
                base_address = self._lastDebugEvent.u.UnloadDll.lpBaseOfDll
                # Remove the unloaded dll from the dlls list
                for dll in self._dlls:
                    if( dll.baseAddress == base_address ):
                        print '%s is unloded' % dll.name
                        self._dlls.remove( dll )
                        
            elif( event_code == win32con.OUTPUT_DEBUG_STRING_EVENT ):
                print "Output string"
            elif( event_code == win32con.RIP_EVENT ):
                print "RIP"
            else:
                print "Unknown debug event! (%d)" % event_code

            if True == self._isDirty:
                FlushInstructionCache(self._process, None, 0)
                self._isDirty = False

    d   = ProcessInspector.readNPrintBin
    dd  = ProcessInspector.readNPrintDwords

    def u( self, address = None, lines = None ):
        """
        Display unassembley (disassembly) of memory
        Gets:
            unsigned long   address
            unsigned long   lines
        """
        if( None == address ):
            self.getCurrentContext()
            address = self.context.eip
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
        data = distorm.Decode( address, data, distorm.Decode32Bits )

        # Print the result
        data[:lines]
        for opcode in data:
            print "0x%08X (%02X) %-20s %s" % (opcode[0], opcode[1], opcode[3], opcode[2])

        return
        
    def getProcAddress( self, dllName, procName ):
        """
        Gets an address to a proc in a dll.
        Gets:
            string      dllName
            string      procName
        Return:
            unsigned long
        """
        module_handle = GetModuleHandle( dllName )
        return( GetProcAddress( module_handle, procName ) )

    def bpx( self, address, proc = pause ):
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
                print 'Already a breakpoint'
                return -1
        # Save the original byte 
        original_byte = self.readByte( address )
        if( BREAK_POINT_BYTE == original_byte ):
            print 'Already a breakpoint - Adding it to the list'
        # Write the int3 opcode
        self.writeByte( address, BREAK_POINT_BYTE )
        self._breakPoints.append( BreakPoint(address, 1, original_byte, proc) )
        return( len(self._breakPoints) - 1 )
        
    def bpl( self ):
        """
        List all break points.
        """
        for break_point in self._breakPoints:
            print str( self._breakPoints.index( break_point ) ),
            if( BREAK_POINT_ACTIVE | break_point.state ):
                # Breakpoint is active.
                print "   ",
            elif( not BREAK_POINT_ACTIVE | break_point.state ):
                # Breakpoint is not active.
                print " * ",
            print hex( break_point.address )
                
    def _bpc( self, break_point ):
        """
        Makes the actually remove of the breakpoint, in a safly way.
        """
        if( BREAK_POINT_ACTIVE | break_point.state ):
            current_byte = self.readByte( break_point.address )
            if( current_byte != break_point.original_byte ):
                raise Excpetion('Somone overwritten the breakpoint!')
            self.writeByte( break_point.address, break_point.original_byte )

    def bpc( self, index ):
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
                self._bpc( break_point )
            self._breakPoints = []
            return

        # Remove a single breakpoint
        break_point = self._breakPoints[index]
        self._bpc( break_point )
        self._breakPoints.remove( break_point )

    def _bpd( self, break_point ):
        if( True == self._areBreakPointsInstalled ):
            if( BREAK_POINT_BYTE != self.readByte( break_point.address ) ):
                print "Program state =", self._state
                raise Excpetion( 'Breakpoint had been overwrite by somthing' )
            self.writeByte( break_point.address, break_point.original_byte )
        break_point.state &= ~BREAK_POINT_ACTIVE

    def bpd( self, index ):
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
                    self._bpd( break_point )
            return
        # Disable a single breakpoint
        break_point = self._breakPoints[index]
        if( not BREAK_POINT_ACTIVE | break_point.state ):
            print "Break point is allread disabled"
            return
        self._bpd( break_point )
        
    def _bpe( self, break_point ):
        if( True == self._areBreakPointsInstalled ):
            self.writeByte( break_point.address, BREAK_POINT_BYTE )
        break_point.state |= BREAK_POINT_ACTIVE

    def bpe( self, index ):
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
                    self._bpe( break_point )
            return
        
        # Enbale a single breakpoint
        break_point = self._breakPoints[index]
        if( BREAK_POINT_ACTIVE | break_point.state ):
            print "Break point is allread enabled"
            return
        self._bpe( break_point )

    def _r( self ):
        """
        Returns the current registers and machine state.
        Returns:
            context
        """
        context = self.context
        return context

    def r( self ):
        """
        Prints the current registers and machine state.
        Returns:
            context
        """
        context = self.context
        string = 'EAX %08X\tECX %08X\tEDX %08X\tEBX %08X\nEDI %08X\tESI %08X\tEBP %08X\tEIP %08X\nSegCs %08X\tEFlags %08X\tESP %08X\tSegSs %08X\n'
        string = string % (context.eax, context.ecx, context.edx, context.ebx, context.edi, context.esi, context.ebp, context.eip, context.segcs, context.eflags, context.esp, context.segss )
        print string
        return context

    def t( self ):
        """
        Trace one opcode
        """
        #self._makeProcessReadyToRun( )
        self._state = PROCESS_STATE_SINGLE_STEP
        self.context.eflags |= 0x100
        self.setCurrentContext( )
        self._uninstallAllBreakPoints( )
        self._g()

###     def __repr__( self ):
###         return( self._r() )
    
    def hideDebugger( self ):
        """
        Rewrites the debugger flag in the PEB

        TBD: not working yet
        """
        self.writeByte( self.readDword(0x7ffde030) + 2, 0 )

    def _uninstallAllBreakPoints( self ):
        """
        Uninstall all break points to handle a break.
        """
        # print 'DEBUG: Uninstall'
        for break_point in self._breakPoints:
            if( BREAK_POINT_ACTIVE | break_point.state ):
                self.writeByte( break_point.address, break_point.original_byte )
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
                self.writeByte( break_point.address, BREAK_POINT_BYTE )
            break_point.state &= ~BREAK_POINT_HIDE

    def _onBreakPoint( self ):
        if( PROCESS_STATE_LOADED == self._state ):
            # First break point.
            self._state = PROCESS_STATE_RUN
            print "Process began..."
            return -1
        elif( PROCESS_STATE_RUN == self._state ):
            # The process was in a middel of normal running
            self._state = PROCESS_STATE_RECOVER_FROM_BREAK_POINT
        # print "Break point"
        eip = self.context.eip - 1
        self._uninstallAllBreakPoints()
        for break_point in self._breakPoints:
            if( break_point.address == eip ):
                # This is one of the user break points
                self.context.eip -= 1
                try:
                    break_point.proc( self )
                except:
                    # The user breakpoint raised an exception...
                    # Print out the traceback, n stop execution
                    traceback.print_exc( sys.exc_info )
                    self.pause()
                # print 'Found break point'
                return self._breakPoints.index( break_point )
        return -1

    def _makeProcessReadyToRun( self ):
        if( PROCESS_STATE_NO_PROCESS == self._state ):
            raise( Excpetion("No process") )
            return
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
        elif( PROCESS_STATE_RECOVER_FROM_TEMP_SINGLE_STEP == self._state ):
            self._state = PROCESS_STATE_RUN
            self._reinstallAllBreakPoints()
            return
        elif( PROCESS_STATE_SINGLE_STEP == self._state ):
            self._state = PROCESS_STATE_RUN
            return
        elif( PROCESS_STATE_RECOVER_FROM_SINGLE_STEP == self._state ):
            self._state = PROCESS_STATE_RUN
            self._reinstallAllBreakPoints()
            return
        else:
            print "Unknown state"
            raise( Excpetion("Error") )



