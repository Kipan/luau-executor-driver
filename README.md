# Luau Bytecode Injector

## Overview
A Windows kernel driver that receives compiled Luau bytecode from a user-mode client via IOCTL and injects it into a target process by overwriting an std::string at a known offset in the process image. Injection is performed by queuing a kernel APC, along with the IRP for direct IO, to a caller-specified thread, causing the bytecode swap to execute in the context of the target process.

## Requirements

- Visual Studio 2022 (v143 toolset)
- Windows Driver Kit (WDK) for Windows 10

## Building

Open `LuaTesting.sln` in Visual Studio with the WDK installed and build the solution in x64 Debug or Release.

## Usage

1. Load the driver (`sc create` / OSR Driver Loader / kdmapper)
2. Run `ClientLuaExecutor.exe` with the target thread ID and a `.luau` script path
3. The client compiles the script to bytecode and sends it to the driver via IOCTL
