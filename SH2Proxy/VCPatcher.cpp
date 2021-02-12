#include "stdafx.h"
#include <iostream>
#include <fstream>
#include "VCPatcher.h"
#include "Hooking.Patterns.h"
#include "Utils.h"
#include <stdio.h>
#include <winternl.h>
#include <ntstatus.h>
#include <windows.h>
#include <tlhelp32.h>
#include <MinHook.h>
#include "UdpPlatformAddress.h"

//FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
#define CONSOLE_ENABLED_THAT_CRASHES

static bool consoleShowing = false;
static float lasttext;

intptr_t* MenuManager = (intptr_t*)0x868638;
void* ConnectionMgrDummy = (void*)0x143B3E498;

#include "timer.h"
#include <iostream>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windows.h>
#include <udis86.h>

#pragma comment(lib, "ws2_32.lib")

static bool(*g_origSetupInitialConnection)(intptr_t a1);
static bool(*g_InitGameWorld)(intptr_t a1);
static bool(*g_orig_TrySignalLaunchPadEvent)(intptr_t a1, void* a2);
static bool(*g_RegisterCommands)();
static void(*g_InitCharacterStuff)(intptr_t a1, intptr_t a2, intptr_t a3, intptr_t a4);
static void(*g_BeginZoningAreaWrapper)(intptr_t a1, float possiblyRadius);

void hexDump(const char* desc, const void* addr, const int len);

static void* FindCallFromAddress(void* methodPtr, ud_mnemonic_code mnemonic = UD_Icall, bool breakOnFirst = false)
{
	// return value holder
	void* retval = nullptr;

	// initialize udis86
	ud_t ud;
	ud_init(&ud);

	// set the correct architecture
	ud_set_mode(&ud, 64);

	// set the program counter
	ud_set_pc(&ud, reinterpret_cast<uint64_t>(methodPtr));

	// set the input buffer
	ud_set_input_buffer(&ud, reinterpret_cast<uint8_t*>(methodPtr), INT32_MAX);

	// loop the instructions
	while (true)
	{
		// disassemble the next instruction
		ud_disassemble(&ud);

		// if this is a retn, break from the loop
		if (ud_insn_mnemonic(&ud) == UD_Iint3 || ud_insn_mnemonic(&ud) == UD_Inop)
		{
			break;
		}

		if (ud_insn_mnemonic(&ud) == mnemonic)
		{
			// get the first operand
			auto operand = ud_insn_opr(&ud, 0);

			// if it's a static call...
			if (operand->type == UD_OP_JIMM)
			{
				// ... and there's been no other such call...
				if (retval == nullptr)
				{
					// ... calculate the effective address and store it
					retval = reinterpret_cast<void*>(ud_insn_len(&ud) + ud_insn_off(&ud) + operand->lval.sdword);

					if (breakOnFirst)
					{
						break;
					}
				}
				else
				{
					// return an empty pointer
					retval = nullptr;
					break;
				}
			}
		}
	}

	return retval;
}

intptr_t LaunchPadA1Ptr;
static bool TrySignalLaunchPadEvent(intptr_t a1, void* a2)
{
	LaunchPadA1Ptr = a1;
	//g_origSetupInitialConnection(a1);
	return g_orig_TrySignalLaunchPadEvent(a1, a2);
}

HANDLE h_console;
static void tryAllocConsole() {
	if (!consoleShowing)
	{
		//Allocate a console
		AllocConsole();
		AttachConsole(GetCurrentProcessId());
		freopen("CON", "w", stdout);
		consoleShowing = true;
		h_console = GetStdHandle(STD_OUTPUT_HANDLE);
	}
}


#ifdef CONSOLE_ENABLED_THAT_CRASHES
static HookFunction hookFunction([]()
	{
	});
#endif

bool ReturnTrue() {
	return true;
}
bool ReturnFalse() {
	return false;
}
extern VCPatcher gl_patcher;

static bool(*g_origConstructDisplay)(intptr_t a1);
static bool ConstructDisplay(intptr_t a1)
{
	g_origConstructDisplay(a1);
	return true; //never fail
}

static bool(*g_origOnReceiveServer)(void* a1, void* a2, void* a3);
static bool OnReceiveServer(void* a1, void* a2, void* a3)
{
	return g_origOnReceiveServer(a1, a2, a3);
}

static SOCKET g_gameSocket;

std::string string_to_hex(const std::string& input)
{
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();

	std::string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	return output;
}

int __stdcall CfxBind(SOCKET s, sockaddr* addr, int addrlen)
{
	sockaddr_in* addrIn = (sockaddr_in*)addr;

	printf_s("binder on %i is %p, %p\n", htons(addrIn->sin_port), (void*)s, _ReturnAddress());

	//if (htons(addrIn->sin_port) == 34567)
	{
		g_gameSocket = s;
	}

	return bind(s, addr, addrlen);
}

int __stdcall CfxRecvFrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)
{
	static char buffer[65536];
	uint16_t netID = 0;
	sockaddr_in* outFrom = (sockaddr_in*)from;
	char addr[60];
	if (s == g_gameSocket)
	{
		inet_ntop(AF_INET, &outFrom->sin_addr.s_addr, addr, sizeof(addr));
		printf_s("CfxRecvFrom (from %i %s) %i bytes on %p, port: %i, %p\n", netID, addr, len, (void*)s, htons(outFrom->sin_port), _ReturnAddress());
	}

	return recvfrom(s, buf, len, flags, from, fromlen);
}

int __stdcall CfxSendTo(SOCKET s, char* buf, int len, int flags, sockaddr* to, int tolen)
{
	sockaddr_in* toIn = (sockaddr_in*)to;

	if (s == g_gameSocket)
	{
		if (toIn->sin_addr.S_un.S_un_b.s_b1 == 0xC0 && toIn->sin_addr.S_un.S_un_b.s_b2 == 0xA8)
		{
			//g_pendSendVar = 0;

			//if (CoreIsDebuggerPresent())
			{
				printf_s("CfxSendTo (to internal address %i) port: %i, %i b (from thread 0x%x), %p\n", (htonl(toIn->sin_addr.s_addr) & 0xFFFF) ^ 0xFEED, htons(toIn->sin_port), len, GetCurrentThreadId(), _ReturnAddress());
				printf_s("CfxSendTo: Data: %s Hex: %s\n", buf, string_to_hex(buf));
			}
		}
		else
		{
			char publicAddr[256];
			inet_ntop(AF_INET, &toIn->sin_addr.s_addr, publicAddr, sizeof(publicAddr));

			if (toIn->sin_addr.s_addr == 0xFFFFFFFF)
			{
				return len;
			}

			printf_s("CfxSendTo (to %s) port: %i, %i b, %p\n", publicAddr, htons(toIn->sin_port), len, _ReturnAddress());
		}

		//g_netLibrary->RoutePacket(buf, len, (uint16_t)((htonl(toIn->sin_addr.s_addr)) & 0xFFFF) ^ 0xFEED);

		//return len;
	}

	return sendto(s, buf, len, flags, to, tolen);
}

int __stdcall CfxSend(SOCKET s, char* buf, int len, int flags)
{

	if (s == g_gameSocket)
	{
		printf_s("CfxSend %i b, %p\n", len, _ReturnAddress());
	}

	return send(s, buf, len, flags);
}

int __stdcall CfxWSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData) {
	return WSAStartup(wVersionRequested, lpWSAData);
}

int __stdcall CfxGetSockName(SOCKET s, struct sockaddr* name, int* namelen)
{
	int retval = getsockname(s, name, namelen);

	sockaddr_in* addrIn = (sockaddr_in*)name;

	if (s == g_gameSocket /*&& wcsstr(GetCommandLine(), L"cl2")*/)
	{
		addrIn->sin_port = htons(6672);
	}

	return retval;
}

static int(__stdcall* g_oldSelect)(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const timeval* timeout);

int __stdcall CfxSelect(_In_ int nfds, _Inout_opt_ fd_set FAR* readfds, _Inout_opt_ fd_set FAR* writefds, _Inout_opt_ fd_set FAR* exceptfds, _In_opt_ const struct timeval FAR* timeout)
{
	bool shouldAddSocket = false;

	for (int i = 0; i < readfds->fd_count; i++)
	{
		if (readfds->fd_array[i] == g_gameSocket)
		{
			memmove(&readfds->fd_array[i + 1], &readfds->fd_array[i], readfds->fd_count - i - 1);
			readfds->fd_count -= 1;
			nfds--;

			/*
			if (g_netLibrary->WaitForRoutedPacket((timeout) ? ((timeout->tv_sec * 1000) + (timeout->tv_usec / 1000)) : INFINITE))
			{
				shouldAddSocket = true;
			}
			*/
		}
	}

	//FD_ZERO(readfds);

	if (nfds > 0)
	{
		nfds = g_oldSelect(nfds, readfds, writefds, exceptfds, timeout);
	}

	if (shouldAddSocket)
	{
		FD_SET(g_gameSocket, readfds);

		nfds += 1;
	}

	return nfds;
}

//ANTI DEBUG
bool IsDebuggerPresentOurs() {
	return true;
}


typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      UINT             ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

int ProcessDebugPort2 = 7;

pfnNtQueryInformationProcess g_origNtQueryInformationProcess = NULL;


static ULONG ValueProcessBreakOnTermination = FALSE;
static bool IsProcessHandleTracingEnabled = false;

DWORD dwExplorerPid = 0;
WCHAR ExplorerProcessName[] = L"explorer.exe";

DWORD GetProcessIdByName(const WCHAR* processName)
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return 0;
	}

	DWORD pid = 0;

	do
	{
		if (!lstrcmpiW((LPCWSTR)pe32.szExeFile, processName))
		{
			pid = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return pid;
}

DWORD GetExplorerProcessId()
{
	if (!dwExplorerPid)
	{
		dwExplorerPid = GetProcessIdByName(ExplorerProcessName);
	}
	return dwExplorerPid;
}

void SetupSetPEB() {
	// Thread Environment Block (TEB)
#if defined(_M_X64) // x64
	PTEB tebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#else // x86
	PTEB tebPtr = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#endif

	// Process Environment Block (PEB)
	PPEB pebPtr = tebPtr->ProcessEnvironmentBlock;
	pebPtr->BeingDebugged = false;
}

static LONG(*g_exceptionHandler)(EXCEPTION_POINTERS*);
static BOOLEAN(*g_origRtlDispatchException)(EXCEPTION_RECORD* record, CONTEXT* context);

static BOOLEAN RtlDispatchExceptionStub(EXCEPTION_RECORD* record, CONTEXT* context)
{
	// anti-anti-anti-anti-debug
	if (IsDebuggerPresentOurs() && (record->ExceptionCode == 0xc0000008/* || record->ExceptionCode == 0xc0000005*/))
	{
		return TRUE;
	}

	BOOLEAN success = g_origRtlDispatchException(record, context);
	//140533ae2
	if (IsDebuggerPresentOurs())
	{
		if (!success) {
			printf("Exception at: %p\n", record->ExceptionAddress);
		}
		return success;
	}

	static bool inExceptionFallback;

	if (!success)
	{
		if (!inExceptionFallback)
		{
			inExceptionFallback = true;

			//AddCrashometry("exception_override", "true");

			EXCEPTION_POINTERS ptrs;
			ptrs.ContextRecord = context;
			ptrs.ExceptionRecord = record;

			if (g_exceptionHandler)
			{
				g_exceptionHandler(&ptrs);
			}

			inExceptionFallback = false;
		}
	}

	return success;
}

void SetupHook()
{
	void* baseAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), "KiUserExceptionDispatcher");

	if (baseAddress)
	{
		void* internalAddress = FindCallFromAddress(baseAddress, UD_Icall, true);

		{
			MH_CreateHook(internalAddress, RtlDispatchExceptionStub, (void**)&g_origRtlDispatchException);
		}
	}

	MH_EnableHook(MH_ALL_HOOKS);
	return;
}

void VCPatcher::PreHooks() {
	SetupSetPEB();
	SetupHook();
}

static void WINAPI ExitProcessReplacement(UINT exitCode)
{
	TerminateProcess(GetCurrentProcess(), exitCode);
}

#if IS_NON_ADMIN_EXE
//showFrameRate(__int64 a1, char a2, __int64 a3, __int64 a4)
//143CC2CD8
void* luaVM = (void*)0x143CC2CD8;
void* unkLuaRel = (void*)0x1421E22F0;
bool* profilerPtr = (bool*)0x142CD9A58;

static hook::cdecl_stub<void(void*, /*LuaVM**/ char* funcName, int, int)> executeLuaFunction([]()
{
	return hook::pattern("48 8D 05 ? ? ? ? 48 89 45 18 45 33 ED 4C 89 6D 20 48 8D 05").count(1).get(0).get<void>(-71);
});

static hook::cdecl_stub<void(void*, /*LuaVM**/ char* funcName)> executeLuaUnk([]()
{
	return hook::pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 8B DA 66 0F 1F 44 00").count(1).get(0).get<void>(-45);
});

static hook::cdecl_stub<void(void*)> doTeleport([]()
{
	return hook::pattern("40 53 48 83 EC 20 48 8D 15 ? ? ? ? 48 8B D9 E8 ? ? ? ? 48 8B 8B ? ? ? ? E8").count(1).get(0).get<void>(0);
});

static hook::cdecl_stub<void(void*, bool zoning, bool forcedLoadingScreen)> BC_WaitForWorldReady([]()
{
	return hook::pattern("40 88 B7 ? ? ? ? 88 9F ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B").count(1).get(0).get<void>(-173);
});

//EB 0A 0F B6 01 88 47 08 48 FF 42 10 48 8D 57 10 48 8B CB E8 ? ? ? ? 48 8B 4B 10 33 F6 48 8D 41 04 48 3B 43 18 76 11 89 77 28 48 -51

static hook::cdecl_stub<void(void*, char* dataBuf)> parseZoneDetails([]()
{
	return hook::pattern("48 8D 57 10 48 8B CB E8 ? ? ? ? 48 8B 4B 10 33 F6 48 8D 41 04 48 3B 43 18 76 11 89 77 28 48").count(1).get(0).get<void>(-63);
});

static hook::cdecl_stub<void(char* inBuffer, int len, char** outBuffer)> dumpPacket([]()
{
	return hook::pattern("4C 89 44 24 ? 89 54 24 10 48 89 4C 24 ? 53 55 57 48 81 EC").count(1).get(0).get<void>(0);
});

static hook::cdecl_stub<void(void* luaVM, char* searchFilter)> filterDataSource([]()
{
	return hook::pattern("40 38 38 74 08 48 FF C0 49 3B C0").count(1).get(0).get<void>(-86);
});

intptr_t CamTickCount = 0;

void* unkArgumentToTP = nullptr;
static bool gameConsoleShowing = false;
static void(*processInput_orig)(void* a1);
static void processInput(void* a1) {

	*(bool*)profilerPtr = true;
	void* vm = *(void**)luaVM;

	if (GetKeyState(VK_F8) & 0x8000)
	{
		//F8 down, open console
		executeLuaFunction(vm, !gameConsoleShowing ? "ConsoleWrapper:Show" : "ConsoleWrapper:Hide", 0, 0);

		gameConsoleShowing = !gameConsoleShowing;
	}

	if (GetKeyState(VK_F7) & 0x8000)
	{
		//F7 down, restore camera

		//filterDataSource(vm, "SendZoneDetails");
		executeLuaFunction(vm, "Ui.CameraRestore", 0, 0);
		CamTickCount = GetTickCount64();
	}

	if (GetKeyState(VK_F6) & 0x8000)
	{
		//F8 down, open console
		executeLuaFunction(vm, "GameEvents:OnPlayerRespawnRequestResponse", 0, 0);
	}

	processInput_orig(a1);
}


static void(*g_orig_TransitionClientRunState)(void* a1, int state, void* a3);
static void TransitionClientRunState(void* a1, int state, void* a3) {
	unkArgumentToTP = a1; //Set it
	g_orig_TransitionClientRunState(a1, state, a3);
}
#endif

static void(*handleInitException_orig)(void* a1, void* a2, void* a3, void* a4);
static void handleInitException(void* a1, void* a2, void* a3, void* a4) {
	__try
	{
		handleInitException_orig(a1, a2, a3, a4);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf_s("handleInitException excepted, caught and returned.\n");
	}
}

static void(*readPayLoad_orig)(void* a1, char* payLoadName, int a3);
static void readPayLoad(void* a1, char* payLoadName, int a3) {
	printf("readPayLoad - payLoadName: %s - Return Address: %p\n", payLoadName, _ReturnAddress());
	readPayLoad_orig(a1, payLoadName, a3);
}

static void(*readPayLoad2_orig)(void* a1, char* payLoadName, int a3);
static void readPayLoad2(void* a1, char* payLoadName, int a3) {
	printf("readPayLoad2 - payLoadName: %s - Return Address: %p\n", payLoadName, _ReturnAddress());
	readPayLoad2_orig(a1, payLoadName, a3);
}

struct IncomingPacket
{
	BYTE gap0[8];
	DWORD packetType;
};

static void(*handleIncomingPackets_orig)(void* thisPtr, IncomingPacket* packet, char* data, int dataLen, float time, int a6);
static void handleIncomingPackets(void* thisPtr, IncomingPacket* packet, char* data, int dataLen, float time, int a6) {
	char* packetDumpOut;
	if (packet->packetType != 60) {
		printf("\n\n\n\n\n\n\n\n\n\n");
		printf("packetType: %d - Return Address: %p\n", packet->packetType, _ReturnAddress());

		if (packet->packetType == 22 || packet->packetType == 3) { //SendZoneDetails and sendself only
			printf("Calling hexDump\n");
			hexDump("data dump for netDataBuf:", data, dataLen);
			printf("\n\n");
			hexDump("data dump for ndbAtLen:", &data[dataLen], dataLen);
		}

		printf("\n\n\n\n\n\n\n\n\n\n");
	}
	handleIncomingPackets_orig(thisPtr, packet, data, dataLen, time, a6);
}

//(void*, /*LuaVM**/ char* funcName, int, int)
static void(*executeLuaFunc_orig)(void* LuaVM, char* funcName, int a3, int a4);
static void executeLuaFuncStub(void* LuaVM, char* funcName, int a3, int a4) {
	void* retAddr = _ReturnAddress();
	if (retAddr != (void*)0x140123F56) {
		printf("executeLuaFuncStub: %s - Return Address: %p\n", funcName, retAddr);
	}
	executeLuaFunc_orig(LuaVM, funcName, a3, a4);
}

static void(*onLoginCompleteStub_orig)(void* thisPtr);
static void onLoginCompleteStub(void* thisPtr) {
	printf("onLoginCompleteStub: Return Address: %p\n", _ReturnAddress());
	onLoginCompleteStub_orig(thisPtr);
}

static void(*handleExternalPackets_orig)(void* a1, void* a2, unsigned int a3);
static void handleExternalPackets(void* a1, void* a2, unsigned int a3) {
	printf("handleExternalPackets: Return Address: %p\n", _ReturnAddress());
	handleExternalPackets_orig(a1, a2, a3);
}




static intptr_t(*g_origWaitForWorldReady)(char* a1);
intptr_t WaitForWorldReady(char* a1) {
	//*(char*)(a1 + 0x38884) = true; //ReceivedPreloadDonePacket
	intptr_t returnVal = 0;
	__try
	{
		returnVal = g_origWaitForWorldReady(a1);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf_s("WaitForWorldReady excepted, caught and returned.\n");
	}
	return 1;
}



void OnIntentionalCrash() {
}

bool VCPatcher::Init()
{
	
	MH_CreateHook((char*)0x140122C30, WaitForWorldReady, (void**)&g_origWaitForWorldReady); //Needs the confirm packet
	// still need this or client crashes right before loading zone -meme
	hook::return_function_vp(0x1408B4230); //crashes

	// remove all badbeef
	hook::nopVP(0x1400301b0, 11);
	hook::nopVP(0x1417b8c18, 11);
	hook::nopVP(0x1417b85d5, 11);
	hook::nopVP(0x1417b4ba9, 11);
	hook::nopVP(0x1417b4ae2, 11);
	hook::nopVP(0x1417b478f, 11);
	hook::nopVP(0x1417b446f, 11);
	hook::nopVP(0x1417b399b, 11);
	hook::nopVP(0x1417b2579, 11);
	hook::nopVP(0x1417ae3ef, 11);
	hook::nopVP(0x1400ddf2c, 11);
	hook::nopVP(0x1400ddcfa, 11);
	hook::nopVP(0x1400dd9f8, 11);
	hook::nopVP(0x1400dd793, 11);
	hook::nopVP(0x1400dd74f, 11);
	hook::nopVP(0x1400d9dd8, 11);
	hook::nopVP(0x1400d9cfa, 11);
	hook::jump(0x1400301B0, OnIntentionalCrash); //Should have crashed, but continue executing...


#if IS_NON_ADMIN_EXE
	//Net Routing
	hook::iat("wsock32.dll", CfxSend, 19);

	hook::iat("wsock32.dll", CfxSendTo, 20);

	//hook::iat("wsock32.dll", CfxRecvFrom, 17);
	hook::iat("wsock32.dll", CfxBind, 2);
	g_oldSelect = hook::iat("wsock32.dll", CfxSelect, 18);
	hook::iat("wsock32.dll", CfxGetSockName, 6);
	hook::iat("wsock32.dll", CfxWSAStartup, 115);
#endif

	MH_CreateHookApi(L"kernel32.dll", "ExitProcess", ExitProcessReplacement, nullptr);

	MH_EnableHook(MH_ALL_HOOKS);

	return true;
}

static struct MhInit
{
	MhInit()
	{
		MH_Initialize();
	}
} mhInit;