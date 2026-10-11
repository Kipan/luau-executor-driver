#pragma once

#define KNOWN_BYTECODE_OFFSET       0x957368
struct MsvcString {
#if defined(DBG) || defined(DEBUG)
	void* Myproxy;    // _Container_proxy*, debug builds only
#endif
    union {
        char  Buf[16];   // SSO buffer (used when _Myres < 16)
        char* Ptr;       // heap pointer (used when _Myres >= 16)
    } Bx;
    SIZE_T Mysize;
    SIZE_T Myres;
};
