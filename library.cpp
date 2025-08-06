//  Copyright (c) 2023 namazso <admin@namazso.eu>
//  
//  Permission to use, copy, modify, and/or distribute this software for any
//  purpose with or without fee is hereby granted.
//  
//  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
//  REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
//  AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
//  INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
//  LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
//  OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
//  PERFORMANCE OF THIS SOFTWARE.

#include <Windows.h>
#include <cstdint>

HINSTANCE get_original_dll() {
  static HINSTANCE p{};
  if (!p)
    p = LoadLibraryExA("XmlLite.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  return p;
}

template <typename Fn>
Fn get_original(const char* name) {
  return (Fn)GetProcAddress(get_original_dll(), name);
}

using fnCreateXmlReader = HRESULT(WINAPI*)(REFIID riid, void** ppvObject, IMalloc* pMalloc);
using fnCreateXmlReaderInputWithEncodingCodePage = HRESULT(WINAPI*)(IUnknown* pInputStream, IMalloc* pMalloc, UINT nEncodingCodePage, BOOL fEncodingHint, LPCWSTR pwszBaseUri, struct IXmlReaderInput** ppInput);
using fnCreateXmlReaderInputWithEncodingName = HRESULT(WINAPI*)(IUnknown* pInputStream, IMalloc* pMalloc, LPCWSTR pwszEncodingName, BOOL fEncodingHint, LPCWSTR pwszBaseUri, struct IXmlReaderInput** ppInput);
using fnCreateXmlWriter = HRESULT(WINAPI*)(REFIID riid, void** ppvObject, IMalloc* pMalloc);
using fnCreateXmlWriterOutputWithEncodingCodePage = HRESULT(WINAPI*)(IUnknown* pOutputStream, IMalloc* pMalloc, UINT nEncodingCodePage, struct IXmlWriterOutput** ppOutput);
using fnCreateXmlWriterOutputWithEncodingName = HRESULT(WINAPI*)(IUnknown* pOutputStream, IMalloc* pMalloc, LPCWSTR pwszEncodingName, struct IXmlWriterOutput** ppOutput);

EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlReader(REFIID riid, void** ppvObject, IMalloc* pMalloc) {
  return get_original<fnCreateXmlReader>("CreateXmlReader")(riid, ppvObject, pMalloc);
}
EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlReaderInputWithEncodingCodePage(IUnknown* pInputStream, IMalloc* pMalloc, UINT nEncodingCodePage, BOOL fEncodingHint, LPCWSTR pwszBaseUri, struct IXmlReaderInput** ppInput) {
  return get_original<fnCreateXmlReaderInputWithEncodingCodePage>("CreateXmlReaderInputWithEncodingCodePage")(pInputStream, pMalloc, nEncodingCodePage, fEncodingHint, pwszBaseUri, ppInput);
}
EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlReaderInputWithEncodingName(IUnknown* pInputStream, IMalloc* pMalloc, LPCWSTR pwszEncodingName, BOOL fEncodingHint, LPCWSTR pwszBaseUri, struct IXmlReaderInput** ppInput) {
  return get_original<fnCreateXmlReaderInputWithEncodingName>("CreateXmlReaderInputWithEncodingName")(pInputStream, pMalloc, pwszEncodingName, fEncodingHint, pwszBaseUri, ppInput);
}
EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlWriter(REFIID riid, void** ppvObject, IMalloc* pMalloc) {
  return get_original<fnCreateXmlWriter>("CreateXmlWriter")(riid, ppvObject, pMalloc);
}
EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlWriterOutputWithEncodingCodePage(IUnknown* pOutputStream, IMalloc* pMalloc, UINT nEncodingCodePage, struct IXmlWriterOutput** ppOutput) {
  return get_original<fnCreateXmlWriterOutputWithEncodingCodePage>("CreateXmlWriterOutputWithEncodingCodePage")(pOutputStream, pMalloc, nEncodingCodePage, ppOutput);
}
EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlWriterOutputWithEncodingName(IUnknown* pOutputStream, IMalloc* pMalloc, LPCWSTR pwszEncodingName, struct IXmlWriterOutput** ppOutput) {
  return get_original<fnCreateXmlWriterOutputWithEncodingName>("CreateXmlWriterOutputWithEncodingName")(pOutputStream, pMalloc, pwszEncodingName, ppOutput);
}

inline void* follow_jumps(void* p) {
    uint8_t* pb = (uint8_t*)p;
    while (true) {
        if (pb[0] == 0xEB) {  // jmp rel8
            pb += 2 + *(int8_t*)&pb[1];
            continue;
        }
        if (pb[0] == 0xE9) {  // jmp rel32
            pb += 5 + *(int32_t*)&pb[1];
            continue;
        }
#ifdef _M_X64
        if (pb[0] == 0xFF && pb[1] == 0x25) { // jmp [rip+imm32]
            int32_t rel = *(int32_t*)&pb[2];
            pb = *(uint8_t**)(pb + 6 + rel);
            continue;
        }
        if (pb[0] == 0x48 && pb[1] == 0xFF && pb[2] == 0x25) { // jmp [rip+imm32] with 48 prefix
            int32_t rel = *(int32_t*)&pb[3];
            pb = *(uint8_t**)(pb + 7 + rel);
            continue;
        }
#else
        if (pb[0] == 0xFF && pb[1] == 0x25) { // jmp [imm32]
            uint32_t addr = *(uint32_t*)&pb[2];
            pb = *(uint8_t**)(uintptr_t)(addr);
            continue;
        }
#endif
        break;
    }
    return pb;
}

inline BOOL hook(void* fn, void* hook_fn) {
    uint8_t* patch = (uint8_t*)follow_jumps(fn);

#ifdef _M_X64
    struct __declspec(align(8)) {
        uint8_t jmp[8] = { 0xFF, 0x25, 0x02, 0x00, 0x00, 0x00, 0x90, 0x90 }; // jmp [RIP+2] + 2 nop
        void* addr;
    } s;
    s.addr = hook_fn;

    DWORD oldProtect;
    if (!VirtualProtect(patch, sizeof(s), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    SIZE_T written = 0;
    BOOL res = WriteProcessMemory(GetCurrentProcess(), patch, &s, sizeof(s), &written);
    if (!res || written != sizeof(s)) {
        VirtualProtect(patch, sizeof(s), oldProtect, &oldProtect);
        return FALSE;
    }

    if (!VirtualProtect(patch, sizeof(s), oldProtect, &oldProtect)) {
        return FALSE;
    }

    if (!FlushInstructionCache(GetCurrentProcess(), patch, sizeof(s))) {
        return FALSE;
    }

    return TRUE;

#else
    uint8_t s[5];
    s[0] = 0xE9; // JMP rel32
    intptr_t relAddr = (intptr_t)hook_fn - (intptr_t)patch - 5;
    memcpy(s + 1, &relAddr, 4);

    DWORD oldProtect;
    if (!VirtualProtect(patch, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    SIZE_T written = 0;
    BOOL res = WriteProcessMemory(GetCurrentProcess(), patch, s, 5, &written);
    if (!res || written != 5) {
        VirtualProtect(patch, 5, oldProtect, &oldProtect);
        return FALSE;
    }

    if (!VirtualProtect(patch, 5, oldProtect, &oldProtect)) {
        return FALSE;
    }

    if (!FlushInstructionCache(GetCurrentProcess(), patch, 5)) {
        return FALSE;
    }

    return TRUE;
#endif
}

LONG WINAPI hooked_CertVerifyTimeValidity(LPFILETIME pTimeToVerify, PCERT_INFO pCertInfo) {
    return 0;
}

VOID WINAPI hooked_GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
    *lpSystemTimeAsFileTime = {};
}

static void initialize() {
    hook((void*)&CertVerifyTimeValidity, (void*)hooked_CertVerifyTimeValidity);
    hook((void*)&GetSystemTimeAsFileTime, (void*)hooked_GetSystemTimeAsFileTime);
}

extern "C" BOOL WINAPI DllEntry(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH)
        initialize();
    return TRUE;
}
