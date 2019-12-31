#include <Windows.h>
#include <string>
#include <iostream>
#include "eyecrawl.h"

std::vector<std::string> LoggedCFunctions;

void LogCFunction(std::string FunctionName, unsigned int Function) {
	std::vector<std::string>::iterator it = std::find(LoggedCFunctions.begin(), LoggedCFunctions.end(), FunctionName);
	if (it == LoggedCFunctions.cend()) {
		std::cout << "[" << FunctionName << "] - 0x" << EyeCrawl::to_str(EyeCrawl::non_aslr(Function)) << " - __" << EyeCrawl::util::calltype(Function) << "\n";
		LoggedCFunctions.push_back(FunctionName);
	}
}

int main()
{
	SetConsoleTitleA("Roblox Address Dumper");
    std::cout << "Finding Roblox... ";

	HWND hWnd;
	HANDLE handle;
	unsigned long id = 0;
	hWnd = FindWindowA(NULL, "Roblox");
	GetWindowThreadProcessId(hWnd, &id);

	handle = OpenProcess(PROCESS_ALL_ACCESS, false, id);
	if (handle == INVALID_HANDLE_VALUE) {
		std::cout << "Failure!\n\n";
		std::cout << "Open Roblox!\n";
		system("PAUSE");
	}

	std::cout << "Success!\n";

	EyeCrawl::open(handle);

	std::cout << "Scanning...\n";
	
	unsigned int MTLockedScan = EyeCrawl::util::scan(EyeCrawl::base_start(), EyeCrawl::base_end(), EyeCrawl::to_bytes("The metatable is locked").c_str(), ".......................")[0];
	unsigned int MTLockedResults = EyeCrawl::util::getprologue(EyeCrawl::util::scanpointer(MTLockedScan)[1]);
	RESULTS MTCFunctions = EyeCrawl::util::getcalls(MTLockedResults);
	std::cout << "";

	LogCFunction("lua_createtable", MTCFunctions[0]);
	LogCFunction("lua_pushstring", MTCFunctions[2]);
	LogCFunction("lua_setfield", MTCFunctions[3]);
	LogCFunction("lua_pushlstring", MTCFunctions[4]);
	LogCFunction("lua_pushvalue", MTCFunctions[5]);
	LogCFunction("lua_settable", MTCFunctions[6]);
	LogCFunction("lua_setmetatable", MTCFunctions[7]);
	LogCFunction("lua_replace", MTCFunctions[8]);
	
	unsigned int LOADEDString = EyeCrawl::util::scan(EyeCrawl::base_start(), EyeCrawl::base_end(), EyeCrawl::to_bytes("_LOADED").c_str(), ".......")[0];
	unsigned int LOADEDResults = EyeCrawl::util::getprologue(EyeCrawl::util::scanpointer(LOADEDString)[0]);
	RESULTS LOADEDCFunctions = EyeCrawl::util::getcalls(LOADEDResults);

	LogCFunction("lua_getfield", LOADEDCFunctions[1]);
	LogCFunction("lua_settop", LOADEDCFunctions[2]);
	LogCFunction("lua_pushvalue", LOADEDCFunctions[4]);
	LogCFunction("lua_setfield", LOADEDCFunctions[5]);
	LogCFunction("lua_remove", LOADEDCFunctions[6]);
	LogCFunction("lua_insert", LOADEDCFunctions[7]);
	LogCFunction("index2adr", LOADEDCFunctions[8]);
	LogCFunction("lua_pushcclosure", LOADEDCFunctions[9]);

	RESULTS BeforeGetFieldCFunctions = EyeCrawl::util::getprologues(LOADEDCFunctions[1], EyeCrawl::behind, 9);

	LogCFunction("lua_call", BeforeGetFieldCFunctions[6]);
	LogCFunction("lua_close", BeforeGetFieldCFunctions[4]);
	LogCFunction("lua_createtable", BeforeGetFieldCFunctions[1]);

	RESULTS AfterPushValueCFunctions = EyeCrawl::util::getprologues(LOADEDCFunctions[4], EyeCrawl::ahead, 7);
	LogCFunction("lua_rawget", AfterPushValueCFunctions[2]);
	LogCFunction("lua_rawgeti", AfterPushValueCFunctions[4]);
	LogCFunction("lua_rawset", AfterPushValueCFunctions[5]);
	LogCFunction("lua_rawseti", AfterPushValueCFunctions[6]);

	RESULTS BeforePushValueCFunctions = EyeCrawl::util::getprologues(LOADEDCFunctions[4], EyeCrawl::behind, 8);

	LogCFunction("lua_pushlightuserdata", BeforePushValueCFunctions[5]);
	LogCFunction("lua_pushnil", BeforePushValueCFunctions[3]);
	LogCFunction("lua_pushnumber", BeforePushValueCFunctions[2]);
	LogCFunction("lua_pushstring", BeforePushValueCFunctions[1]);
	LogCFunction("lua_pushthread", BeforePushValueCFunctions[0]);

	RESULTS BeforePushCClosure = EyeCrawl::util::getprologues(LOADEDCFunctions[9], EyeCrawl::behind, 8);

	LogCFunction("lua_newthread", BeforePushCClosure[5]);
	LogCFunction("lua_newuserdata", BeforePushCClosure[4]);
	LogCFunction("lua_next", BeforePushCClosure[3]);
	LogCFunction("lua_objlen", BeforePushCClosure[2]);
	LogCFunction("lua_pcall", BeforePushCClosure[1]);
	LogCFunction("lua_pushboolean", BeforePushCClosure[0]);

	RESULTS BeforeSetField = EyeCrawl::util::getprologues(LOADEDCFunctions[5], EyeCrawl::behind, 2);
	LogCFunction("lua_resume", BeforeSetField[1]);

	RESULTS AfterSetField = EyeCrawl::util::getprologues(LOADEDCFunctions[5], EyeCrawl::ahead, 4);

	LogCFunction("lua_setmetatable", AfterSetField[2]);
	LogCFunction("lua_setreadonly", AfterSetField[3]);

	unsigned int SCScan = EyeCrawl::util::scan(EyeCrawl::base_start(), EyeCrawl::base_end(), EyeCrawl::to_bytes("Script Context").c_str(), "")[1];
	unsigned int SCScanResult = EyeCrawl::util::getprologue(EyeCrawl::util::scanpointer(SCScan)[0]);
	printf("ScriptContextVFTable: 0x%08X.\n", EyeCrawl::non_aslr(EyeCrawl::util::getpointers(SCScanResult)[2]));

	std::cout << "";
	std::cout << "Success!\n";

	system("PAUSE");
	return 0;
}

