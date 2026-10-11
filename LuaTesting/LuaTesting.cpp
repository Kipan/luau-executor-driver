// LuaTesting.cpp : Minimal Luau engine that re-runs a single script every 10 seconds.
//

#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <limits>

#include "Luau/BytecodeBuilder.h"
#include "Luau/Compiler.h"
#include "lua.h"
#include "lualib.h"

static const char* kScriptPath = "script.luau";
static const auto kInterval = std::chrono::seconds(10);

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

static void RunScript(lua_State* L, std::string bytecode)
{

    // Run each execution on its own thread so globals set by one run don't leak into the next.
    lua_State* T = lua_newthread(L);
    luaL_sandboxthread(T);

    // luau_load also reports compile errors, which Luau encodes into the bytecode blob.
    if (luau_load(T, "=script", bytecode.data(), bytecode.size(), 0) != 0)
    {
        std::cerr << "Load error: " << lua_tostring(T, -1) << "\n";
    }
    else if (lua_pcall(T, 0, 0, 0) != LUA_OK)
    {
        std::cerr << "Runtime error: " << lua_tostring(T, -1) << "\n";
    }

    lua_pop(L, 1); // pop the thread so it can be collected
}

int main()
{
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    lua_State* L = luaL_newstate();
    luaL_openlibs(L);
    luaL_sandbox(L);

    std::string source;
    if (!ReadFile(kScriptPath, source))
    {
        std::cerr << "Could not open " << kScriptPath << "\n";
        return 0;
    }

    static std::string bytecode = CompileScript(source);

    for (;;)
    {
        RunScript(L, bytecode);
        lua_gc(L, LUA_GCCOLLECT, 0);
        fflush(stdout);
        std::this_thread::sleep_for(kInterval);
    }

    lua_close(L);
    return 0;
}
