#include <ntifs.h>
#include <wdm.h>
#include <intrin.h>

#include "KApcInjector.h"
#include "LuaExecutorPublic.h"
#include "RequestState.h"
#include "LuaExecutor.h"

RequestState *g_requestState;

void* __cdecl operator new(size_t size, POOL_FLAGS pool, ULONG tag = DRIVER_TAG) {
	return ExAllocatePool2(pool, size, tag);
}

void __cdecl operator delete(void* ptr, size_t size, std::align_val_t alignment) noexcept
{
    UNREFERENCED_PARAMETER(size);
    UNREFERENCED_PARAMETER(alignment);
    if (ptr) {
        ExFreePool(ptr);
    }
}


NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR info) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

void LuaExecUnload(PDRIVER_OBJECT DriverObject) {
	delete g_requestState;
	UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\ApcInjector");
	IoDeleteSymbolicLink(&symlink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS LuaExecControl(PDEVICE_OBJECT , PIRP Irp) {
	auto irpSp = IoGetCurrentIrpStackLocation(Irp);
	auto& dic = irpSp->Parameters.DeviceIoControl;
	ULONG outLen = dic.OutputBufferLength;
	auto status = STATUS_INVALID_DEVICE_REQUEST;

	switch (dic.IoControlCode) {
	case IOCTL_WRITE_EXEC_REQUEST:
		if (Irp->MdlAddress == nullptr ||
			outLen < LUA_EXEC_REQUEST_HEADER_SIZE ||
			outLen > LUA_EXEC_REQUEST_HEADER_SIZE + LUA_EXEC_REQUEST_MAX_DATA_LENGTH) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto req = (PLUA_EXEC_REQUEST)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		if (req == nullptr) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		if (req->BytecodeLength > outLen - LUA_EXEC_REQUEST_HEADER_SIZE ||
			req->BytecodeLength > LUA_EXEC_REQUEST_MAX_DATA_LENGTH) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		status = g_requestState->AddRequest(Irp);

		if (!NT_SUCCESS(status))
			break;
		//info = dic.InputBufferLength;
		break;
	}

	if (!NT_SUCCESS(status))
		return CompleteRequest(Irp, status, 0);
	return STATUS_PENDING;
}

NTSTATUS RequestState::AddRequest(PIRP Irp) {
	KdPrint((DRIVER_PREFIX "State::AddRequests()\n"));

	auto fullRequest = (FullRequest*)ExAllocateFromNPagedLookasideList(&m_lookaside);
	if (fullRequest == nullptr)
		return STATUS_INSUFFICIENT_RESOURCES;
	fullRequest->Irp = Irp;

	Locker locker(m_lock);
	InsertTailList(&m_head, &fullRequest->Link);

	KeReleaseSemaphore(&m_counter, 2, 1, FALSE);
	KdPrint(("Semaphore count: %u\n", KeReadStateSemaphore(&m_counter)));
	IoMarkIrpPending(Irp);
	return STATUS_SUCCESS;
}

NTSTATUS LuaExecCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	if (IoGetCurrentIrpStackLocation(Irp)->MajorFunction == IRP_MJ_CREATE) {
		status = g_requestState->Start(DeviceObject);
	}
	return CompleteRequest(Irp, status);
}


NTSTATUS RequestState::Start(PVOID IoObject) {
	Locker lock(m_lock);
	if (m_hThread) {
		return STATUS_SUCCESS;
	}
	return IoCreateSystemThread(
		IoObject,
		&m_hThread,
		THREAD_ALL_ACCESS,
		nullptr,
		nullptr,
		nullptr,
		InjectApc,
		this
	);
}

void RequestState::InjectApc(PVOID context) {
	((RequestState*)context)->InjectApc();
}

VOID ApcRoutine(
    PKAPC Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	NTSTATUS status = STATUS_SUCCESS;
	auto request = CONTAINING_RECORD(Apc, FullRequest, apc);

	do {
		// Get the client buffer
		PLUA_EXEC_REQUEST clientReq = nullptr;
		clientReq = g_requestState->GetClientRequestFromIrp(request->Irp);
		if (clientReq == nullptr) {
			KdPrint(("ApcRoutine: could not get client request from irp"));
			status = STATUS_INVALID_ADDRESS;
			break;
		}

		// do stuff
		KdPrint(("Running under the context of TID %u!\n", clientReq->Tid));
		/*
		ULONG64 cr4 = __readcr4();
		__writecr4(cr4 & ~(1ULL << 20)); // clear SMEP

		// lua stuff here

		__writecr4(cr4 | (1ULL << 20)); // restore SMEP
		*/
		PEPROCESS targetProcess = IoThreadToProcess(request->targetThread);
		PVOID imageBase = PsGetProcessSectionBaseAddress(targetProcess);
		if (imageBase == nullptr) {
			KdPrint(("Failed to get target base"));
			status = STATUS_NOT_FOUND;
			break;
		}

		auto bytecodeStr = (MsvcString*)((ULONG_PTR)imageBase +  KNOWN_BYTECODE_OFFSET);
		SIZE_T newSize = clientReq->BytecodeLength;
		if (newSize <= bytecodeStr->Myres) {
			// New bytecode fits in the existing heap allocation — write in place
			char* dest = (bytecodeStr->Myres >= 16) ? bytecodeStr->Bx.Ptr : bytecodeStr->Bx.Buf;
			RtlCopyMemory(dest, clientReq->Bytecode, newSize);
			dest[newSize] = '\0';
			bytecodeStr->Mysize = newSize;
		}
		else {
			// Need a larger buffer — allocate in the target process VA
			PVOID newBuf = nullptr;
			SIZE_T allocSize = newSize + 1;
			status = ZwAllocateVirtualMemory(
				ZwCurrentProcess(), &newBuf, 0, &allocSize,
				MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
			);
			if (!NT_SUCCESS(status))
				break;

			RtlCopyMemory(newBuf, clientReq->Bytecode, newSize);
			((char*)newBuf)[newSize] = '\0';

			// Old heap buffer is a CRT alloc — leak it rather than crashing by
			// calling VirtualFree on it. The process lifetime is short anyway.
			bytecodeStr->Bx.Ptr = (char*)newBuf;
			bytecodeStr->Mysize = newSize;
			bytecodeStr->Myres = allocSize - 1;
		}
	} while (false);

	CompleteRequest(request->Irp, status, 0);
	g_requestState->FreeRequest(request);
}

VOID ApcRundownRoutine(PKAPC Apc)
{
    auto request = CONTAINING_RECORD(Apc, FullRequest, apc);

	// Thread exited before APC fired
	CompleteRequest(request->Irp, STATUS_UNSUCCESSFUL, 0);

    // Free request
	g_requestState->FreeRequest(request);
}

void RequestState::Stop() {
	if (m_hThread) {
		KeSetEvent(&m_stopEvent, 1, FALSE);
		//
		// wait for thread to exit loop
		//
		PVOID thread;
		auto status = ObReferenceObjectByHandle(m_hThread, SYNCHRONIZE, *PsThreadType, KernelMode, &thread, nullptr);
		if (!NT_SUCCESS(status)) {
			KdPrint(("ObReferenceObjectByHandle failed to get thread object"));
		}
		else {
			KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, nullptr);
			ObDereferenceObject(thread);
		}
		ZwClose(m_hThread);
		m_hThread = nullptr;
	}
}

PLUA_EXEC_REQUEST RequestState::GetClientRequestFromIrp(PIRP Irp)
{
    if (Irp->MdlAddress == nullptr)
        return nullptr;
    return (PLUA_EXEC_REQUEST)
        MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
}

void RequestState::InjectApc() {
	auto status = STATUS_SUCCESS;
	PVOID objects[] = { &m_counter, &m_stopEvent };
	for (;;) {
		status = KeWaitForMultipleObjects(2, objects, WaitAny, Executive, KernelMode, FALSE, nullptr, nullptr);
		if (status == STATUS_WAIT_1) {
			KdPrint((DRIVER_PREFIX "Injector thread signaled, exiting\n"));
			break;
		}
		// semaphore signaled
		KdPrint(("Semaphore count: %u\n", KeReadStateSemaphore(&m_counter)));

		PLIST_ENTRY link;
		{
			Locker locker(m_lock);
			link = RemoveHeadList(&m_head);
			NT_ASSERT(link != &m_head);
		}
		auto request = CONTAINING_RECORD(link, FullRequest, Link);
		PLUA_EXEC_REQUEST clientReq = nullptr;
		clientReq = GetClientRequestFromIrp(request->Irp);
		if (clientReq == nullptr) {
			KdPrint(("ApcRoutine: could not get client request from irp"));
			CompleteRequest(request->Irp, STATUS_UNSUCCESSFUL, 0);
			FreeRequest(request);
			continue;
		}
		KdPrint(("Processing request, TID=%u\n", clientReq->Tid));

		status = PsLookupThreadByThreadId(ULongToHandle(clientReq->Tid), &request->targetThread);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "Failed to get handle to target thread"));
			CompleteRequest(request->Irp, STATUS_UNSUCCESSFUL, 0);
			FreeRequest(request);
			continue;
		}
		KeInitializeApc(
			&request->apc,
			request->targetThread,
			OriginalApcEnvironment,
			ApcRoutine,
			ApcRundownRoutine,
			nullptr,
			KernelMode,
			nullptr
		);
		if (!KeInsertQueueApc(&request->apc, nullptr, nullptr, IO_NO_INCREMENT)) {
			CompleteRequest(request->Irp, STATUS_UNSUCCESSFUL, 0);
			FreeRequest(request);
			continue;
		}
	}
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	KdPrint(("in entry"));
	g_requestState = new (POOL_FLAG_NON_PAGED) RequestState;
	if (g_requestState == nullptr) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	auto status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\LuaExec");

	do {
		UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\LuaExec");
		status = IoCreateDevice(DriverObject, 0, &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
		if (!NT_SUCCESS(status))
			break;

		DriverObject->Flags |= DO_DIRECT_IO;
		status = IoCreateSymbolicLink(&symlink, &name);
		if (!NT_SUCCESS(status))
			break;
	} while (false);

	if (!NT_SUCCESS(status)) {
		delete g_requestState;
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);
		return status;
	}


	DriverObject->DriverUnload = LuaExecUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = LuaExecCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = LuaExecControl;
	return status;
}