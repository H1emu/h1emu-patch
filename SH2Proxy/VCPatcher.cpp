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


void SetupHook()
{
	void* baseAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), "KiUserExceptionDispatcher");

	if (baseAddress)
	{
		void* internalAddress = FindCallFromAddress(baseAddress, UD_Icall, true);

	}

	MH_EnableHook(MH_ALL_HOOKS);
	return;
}

void VCPatcher::PreHooks() {
	SetupSetPEB();
	SetupHook();
}


void* luaVM = (void*)0x143CC2CD8;
void* unkLuaRel = (void*)0x1421E22F0;
bool* profilerPtr = (bool*)0x142CD9A58;

static hook::cdecl_stub<void(void*, /*LuaVM**/ char* funcName, int, int)> executeLuaFunction([]()
{
	return hook::pattern("48 8D 05 ? ? ? ? 48 89 45 18 45 33 ED 4C 89 6D 20 48 8D 05").count(1).get(0).get<void>(-71);
});

static hook::cdecl_stub<void(void*, bool zoning, bool forcedLoadingScreen)> BC_WaitForWorldReady([]()
{
	return hook::pattern("40 88 B7 ? ? ? ? 88 9F ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B").count(1).get(0).get<void>(-173);
});



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
	processInput_orig(a1);
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

struct __declspec(align(2)) DataLoadByPacket
{
	char* _buffer;
	int bufferSize;
	char gapC[4];
	char* pBuffer;
	char* pBufferEnd;
	__int16 failureFlag;
};

static void(*ItemDefinitionReadFromBuffer_orig)(void* a1, DataLoadByPacket* buffer);
static void ItemDefinitionReadFromBuffer(void* a1, DataLoadByPacket* buffer) {
	if (buffer->pBuffer + 4 <= buffer->pBufferEnd)
	{
		buffer->pBuffer = buffer->pBuffer + 4;                   // ID
	}
	else
	{
		buffer->failureFlag = 1;
		buffer->pBuffer = buffer->pBufferEnd;
	}
	ItemDefinitionReadFromBuffer_orig(a1, buffer);
}

bool VCPatcher::Init()
{
	
	//MH_CreateHook((char*)0x140122C30, WaitForWorldReady, (void**)&g_origWaitForWorldReady); //Needs the confirm packet
	// still need this or client crashes right before loading zone -meme
	hook::return_function_vp(0x1408B4230); //crashes

    hook::jump(0x1400301B0, OnIntentionalCrash); //Should have crashed, but continue executing...

	MH_CreateHook((char*)0x14019AFB0, processInput, (void**)&processInput_orig);

	MH_CreateHook((char*)0x14045F9F0, ItemDefinitionReadFromBuffer, (void**)&ItemDefinitionReadFromBuffer_orig);


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