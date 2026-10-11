#pragma once


struct FastMutex {
	FastMutex() {
		KeInitializeMutex(&_mutex, 0);
	}
	void Lock() {
		KeWaitForSingleObject(&_mutex, Executive, KernelMode, FALSE, nullptr);
	}

	void Unlock() {
		KeReleaseMutex(&_mutex, FALSE);
	}

private:
	KMUTEX _mutex;
};

template<typename TLock> struct Locker {
	explicit Locker(TLock& lock) : _lock(lock) {
		lock.Lock();
	}
	~Locker() {
		_lock.Unlock();
	}

private:
	TLock& _lock;
};

struct FullRequest {
	LIST_ENTRY Link;
	KAPC apc;
	PIRP Irp;
	PETHREAD targetThread = nullptr;
};

struct RequestState {
	RequestState();
	~RequestState();

	NTSTATUS AddRequest(PIRP Irp);
	NTSTATUS Start(PVOID IoObject);
	void Stop();

	PLUA_EXEC_REQUEST GetClientRequestFromIrp(PIRP Irp);

	void FreeRequest(FullRequest* request)
    {
        if (request->targetThread != nullptr)
        {
			KdPrint((DRIVER_PREFIX "Dereferencing thread object"));
            ObDereferenceObject(request->targetThread);
            request->targetThread = nullptr;
        }

        ExFreeToNPagedLookasideList(
            &m_lookaside,
            request
        );
    }

private:
	static void InjectApc(PVOID context);
	void InjectApc();

	LIST_ENTRY m_head;
	FastMutex m_lock;
	KSEMAPHORE m_counter;
	KEVENT m_stopEvent;
	HANDLE m_hThread{ nullptr };
	NPAGED_LOOKASIDE_LIST m_lookaside;

};

RequestState::RequestState() {
	InitializeListHead(&m_head);
	KeInitializeSemaphore(&m_counter, 0, 1000);
	KeInitializeEvent(&m_stopEvent, SynchronizationEvent, FALSE);
	ExInitializeNPagedLookasideList(&m_lookaside, nullptr, nullptr, 0, sizeof(FullRequest), DRIVER_TAG, 0);
}

RequestState::~RequestState() {
	Stop();
	ExDeleteNPagedLookasideList(&m_lookaside);
}
