#pragma once

#define DRIVER_TAG 'ccuf'
#define DRIVER_PREFIX "LuaExecutor: "

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);


// KAPC functions/structs
typedef VOID(*PKRUNDOWN_ROUTINE) (IN struct _KAPC* Apc);

typedef VOID(*PKNORMAL_ROUTINE) (IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	);

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID(*PKKERNEL_ROUTINE) (
	IN struct _KAPC* Apc,
	IN OUT PKNORMAL_ROUTINE* NormalRoutine,
	IN OUT PVOID* NormalContext,
	IN OUT PVOID* SystemArgument1,
	IN OUT PVOID* SystemArgument2
	);

extern "C" {
	NTKERNELAPI VOID KeInitializeApc(
		IN PRKAPC Apc,
		IN PKTHREAD Thread,
		IN KAPC_ENVIRONMENT Environment,
		IN PKKERNEL_ROUTINE KernelRoutine,
		IN PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL,
		IN PKNORMAL_ROUTINE NormalRoutine OPTIONAL,
		IN KPROCESSOR_MODE ApcMode,
		IN PVOID NormalContext
	);

	NTKERNELAPI BOOLEAN KeInsertQueueApc(IN PRKAPC Apc,
		IN PVOID SystemArgument1,
		IN PVOID SystemArgument2,
		IN KPRIORITY Increment
	);
	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(
		_In_ PEPROCESS Process
	);
}
