// ApcInjectClient.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <limits>

#include <Windows.h>
#include <stdio.h>
#include <vector>
#include "..\LuaExecutor\LuaExecutorPublic.h"

#include "Luau/BytecodeBuilder.h"
#include "Luau/Compiler.h"

static const char* kScriptPath = "inject_script.luau";

int Error(const char* message) {
	printf("%s (error=%u)\n", message, GetLastError());
	return 1;
}

// Hook for transforming instructions after compilation. The stock Luau VM
// expects unmodified opcodes, so this encoder leaves them untouched.
class BytecodeEncoder : public Luau::BytecodeEncoder
{
public:
    void encode(uint32_t* data, size_t count) override
    {
        (void)data;
        (void)count;
    }
};

std::string CompileScript(const std::string& source)
{
    Luau::CompileOptions options = {};
    options.debugLevel = 1;
    options.optimizationLevel = 1;
    options.vectorLib = "Vector3";
    options.vectorCtor = "new";
    options.vectorType = "Vector3";

    static BytecodeEncoder encoder;
    return Luau::compile(source, options, {}, &encoder);
}

static bool ReadFile(const char* path, std::string& out)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return false;

    std::stringstream buffer;
    buffer << file.rdbuf();
    out = buffer.str();
    return true;
}


int main(int argc, const char* argv[]) {
	if (argc < 2) {
		printf("usage: ClientLuaExecutor <threadid>");
		return 0;
	}

	int tid = atoi(argv[1]);

	HANDLE hDevice = CreateFile(L"\\\\.\\LuaExec", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE)
		return Error("failed to open driver");

	//LUA_EXEC_REQUEST request[1];
	//request[0].Tid = tid;

	std::string source;
    if (!ReadFile(kScriptPath, source))
    {
        std::cerr << "Could not open " << kScriptPath << "\n";
        return 0;
    }

    std::string bytecode = CompileScript(source);


	ULONG totalSize = LUA_EXEC_REQUEST_HEADER_SIZE + static_cast<ULONG>(bytecode.size());
	std::vector<BYTE> buf(totalSize);
	PLUA_EXEC_REQUEST req = reinterpret_cast<PLUA_EXEC_REQUEST>(buf.data());
	req->Tid = tid;
	req->BytecodeLength = static_cast<ULONG>(bytecode.size());
	memcpy(req->Bytecode, bytecode.data(), bytecode.size());

	DWORD bytes;
	if (!DeviceIoControl(
		hDevice,
		IOCTL_WRITE_EXEC_REQUEST,
		nullptr,
		0,
		req,
		totalSize,
		&bytes,
		nullptr)) {
		return Error("Failed in DeviceIoControl");
	}
	
	printf("DeviceIoControl succeeded");
	CloseHandle(hDevice);
}
