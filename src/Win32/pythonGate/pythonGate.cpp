#include "framework.h"

typedef void (* Py_InitializeEx_t)(int initsigs);
typedef int (* PyRun_SimpleString_t)(const char * command);

constexpr wchar_t PYTHON_DLL[]{ L"python37.dll" };

DWORD WINAPI startPythonProcess(
	_In_ LPVOID)
{
	auto pythonDll = LoadLibrary(PYTHON_DLL);
	Py_InitializeEx_t Py_InitializeEx = reinterpret_cast<Py_InitializeEx_t>(
		GetProcAddress(pythonDll, "Py_InitializeEx"));
	PyRun_SimpleString_t PyRun_SimpleString = reinterpret_cast<PyRun_SimpleString_t>(
		GetProcAddress(pythonDll, "PyRun_SimpleString"));
	Py_InitializeEx(0);
	auto script = "import rpyc; "
		"s = rpyc.core.service.ClassicService(); "
		"t = rpyc.utils.server.ThreadedServer(s, 'localhost', port=12345); "
		"t.start()";
	int scriptResult = PyRun_SimpleString(script);

	return scriptResult;
}

BOOL APIENTRY DllMain(
	_In_ HMODULE,
	_In_ DWORD  reasonForCall,
	_In_ LPVOID)
{
    switch (reasonForCall)
    {
    case DLL_PROCESS_ATTACH:
		CreateThread(
			nullptr,
			0,
			static_cast<LPTHREAD_START_ROUTINE>(&startPythonProcess),
			nullptr,
			0,
			nullptr);
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
        break;
	default:
		break;
    }
    return TRUE;
}

extern "C" void APIENTRY haltAndCatchFire()
{
	for (;;) {
		Sleep(0);
	}
}