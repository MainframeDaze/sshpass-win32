#include <windows.h>
#include <wincred.h>
#include <string>
#include "Credentials.h"

#pragma comment(lib, "Advapi32.lib")

/**
 * get_vault_pass:
 * Reads a Generic credential from Credential Manager using a UTF?16 tag,
 * converts the password to ANSI, and returns it in a length?tracked buffer.
 * For the MOST SECURE buffer, use VirtualAlloc/Lock to keep the info out of
 * the Page File as much as possible. At present, I don't care that much. Nice
 * thing is the alloc method is 100% internal to this code so it would be easy
 * to change.
 * 
 * If an empty SecretBuffer is returned, check GetLastError(). If non-empty then
 * the caller should use final_burn() to clear and free the buffer. The 
 */
SecretBuffer get_vault_pass(const char* tag) {
    SecretBuffer out{ nullptr, 0 };
    PCREDENTIALW pCred = nullptr;

    // Convert ANSI tag ? UTF?16
    int wlen = MultiByteToWideChar(CP_ACP, 0, tag, -1, nullptr, 0);
    if (wlen <= 0) return out;

    std::wstring wtag(wlen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, tag, -1, &wtag[0], wlen);

    // Read the credential (Unicode API)
    if (!CredReadW(wtag.c_str(), CRED_TYPE_GENERIC, 0, &pCred)) {
        // Failed - see GetLastError()
        return out;
    }

    // No secret stored
    if (pCred->CredentialBlobSize == 0) {
        CredFree(pCred);
        SetLastError(ERROR_NOT_FOUND);      // same as if the credential is not found (it is empty)
        return out;
    }

    // Interpret the blob as UTF?16 characters
    DWORD wcharCount = pCred->CredentialBlobSize / sizeof(WCHAR);
    LPCWCH secretW = reinterpret_cast<LPCWCH>(pCred->CredentialBlob);       // Unicode pointer into Credential Buffer for PW

    // Convert UTF?16 ? ANSI
    int ansiLen = WideCharToMultiByte(
        CP_ACP,
        0,
        secretW,
        wcharCount,
        nullptr,
        0,
        nullptr,
        nullptr
    );

    if (ansiLen <= 0) {
        // This is Windows memory -- we CANNOT WIPE IT, just let it go with CredFree()
        CredFree(pCred);
        return out;
    }

    // Allocate ANSI buffer from the process heap. Up to caller to use "final_burn" to zero and then free this memory
    char* buf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ansiLen + 1);
    if (!buf) {
        CredFree(pCred);
        return out;
    }

    WideCharToMultiByte(
        CP_ACP,
        0,
        secretW,
        wcharCount,
        buf,
        ansiLen,
        nullptr,
        nullptr
    );

    buf[ansiLen] = '\0';

    out.data = buf;
    out.len = ansiLen;      // char count, NOT BUFFER SIZE (buffer is ansiLen + 1)

    CredFree(pCred);
    return out;
}

/**
 * final_burn:
 * Securely wipes and frees the ANSI buffer.
 */
void final_burn(SecretBuffer& s) {
    if (s.data) {
        SecureZeroMemory(s.data, s.len);        // s.len DOES NOT include the trailing NULL but then we do not need to ZERO the NULL :)
        HeapFree(GetProcessHeap(), 0, s.data);
        s.data = nullptr;
        s.len = 0;
    }
}
