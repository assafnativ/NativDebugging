from .Win32Structs import *
import os

class Detours( object ):
    def __init__( self ):
        self._POINTER_SIZE = sizeof(c_void_p)
        self._is_win64 = (self._POINTER_SIZE == 8)
        dllPath = os.path.dirname(os.path.abspath(__file__))
        if self._is_win64:
            self.detoursDll = WinDLL(os.path.join(dllPath, 'DetoursAMD64.dll'))
        else:
            self.detoursDll = WinDLL(os.path.join(dllPath, 'Detoursx86.dll'))
        self._definedetoursDll(self.detoursDll)
        self.originalFunctions = {}

    def _definedetoursDll(self, detoursDll):
        self.transactionBegin = detoursDll.DetourTransactionBegin
        self.transactionBegin.argtypes = []
        self.transactionBegin.restype = ErrorIfNotZero
        self.transactionAbort = detoursDll.DetourTransactionAbort
        self.transactionAbort.argtypes = []
        self.transactionAbort.restype = ErrorIfNotZero
        self.transactionCommit = detoursDll.DetourTransactionCommit
        self.transactionCommit.argtypes = []
        self.transactionCommit.restype = ErrorIfNotZero
        self.transactionCommitEx = detoursDll.DetourTransactionCommitEx
        self.transactionCommitEx.argtypes = [ c_void_p ]
        self.transactionCommitEx.restype = ErrorIfNotZero
        self.updateThread = detoursDll. DetourUpdateThread
        self.updateThread.argtypes = [ c_void_p ]
        self.updateThread.restype = ErrorIfNotZero
        self.attach = detoursDll.DetourAttach
        self.attach.argtypes = [
                c_void_p,       # _Inout_ PVOID *ppPointer
                c_void_p ]      # _In_ PVOID pDetour
        self.attach.restype = ErrorIfNotZero
        self.attachEx = detoursDll.DetourAttachEx
        self.attachEx.argtypes = [
                c_void_p, #_Inout_ PVOID *ppPointer
                c_void_p, #_In_ PVOID pDetour
                c_void_p, #_Out_opt_ PDETOUR_TRAMPOLINE *ppRealTrampoline
                c_void_p, #_Out_opt_ PVOID *ppRealTarget
                c_void_p ] #_Out_opt_ PVOID *ppRealDetour
        self.attachEx.restype = ErrorIfNotZero
        self.detach = detoursDll.DetourDetach
        self.detach.argv = [
                c_void_p,   # _Inout_ PVOID *ppPointer
                c_void_p ]  # _In_ PVOID pDetour
        self.detach.restype = ErrorIfNotZero

    def getCTypeProcAddress(self, proc):
        return cast(proc, c_void_p).value

    def hook(self, targetAddress, targetPrototype, c_newProc):
        self.transactionBegin()
        self.updateThread(GetCurrentThread())
        original = c_void_p(targetAddress)
        self.attach(byref(original), c_newProc)
        self.transactionCommit()
        self.originalFunctions[targetAddress] = cast(original, targetPrototype)



