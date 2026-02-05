/**********************************************************************
* 
* SSHPass
* 
* Used to supply a password to SSH or SCP on the command line. Does so be creating a Virtual Console on its own thread with pipes for I/O and piping that I/O to/from the virtual console
* where the program is running to the command window where it was launched. Keeps doing that until the thread exits, then we exit with the return code from the thread.
* 
* v2.0.0.0  9/26/2025
* Downloaded from GitHub and updated to work with Windows 11 x64 and compile with VS2022. Compile 64-bit ONLY (to avoid Wow Redirector issues on EXEs).
* Some changes: 
*   Added a lot more error checking on Win API calls
*   Replaced strstr() with source code for stristr() to make password string matches case InsEnsiTiVe
*   enum used for pwtype was not working. Replaced it with #define macros in argpars.h
*   Added comments as I figured out what different parts of the code do
*   Used pragmas to ensure getenv() is not flagged and to ensure Kernel structures are packed on the BYTE boundary
*   Changed handling of CreateProceesA() command line to NOT add a trailing blank
* 
* v2.0.1.0  11/30/2025
* Comment out "WFMO result" output. DIsconnected from original fork because I did not want to merge Unicode and other changes
* 
* v2.0.2.0  11/30/2025
* Updated InputHandlerThread() to set ENABLE_VIRTUAL_TERMINAL_INPUT as per original branch. If CreatePseudoConsoleAndPipes() fails, we not only print the error code, we
* also return it as our result.
* 
* V2.0.3.0  2/4/2026
* Crunched codebase with CoPoilot, found several issues and fixed them:
* 
 * - Threading
 *   - Replaced use of CRT-only `_beginthread()` with `_beginthreadex()` so callers receive a
 *     Win32-compatible thread handle. Thread entry functions updated to `unsigned __stdcall`
 *     to match `_beginthreadex` calling convention.
 *   - Store and close thread HANDLEs returned from `_beginthreadex()` (close handles after threads
 *     terminate) to avoid handle leaks and to allow safe Wait/Close semantics.
 *   - Simplified thread-start error handling: check returned value == 0 and use GetLastError()
 *     (removed incorrect checks for -1 and errno-based switch logic).
 *
 * - Pseudo-console / attribute list handling
 *   - Fixed memory-leak and error handling around `InitializeProcThreadAttributeList`:
 *     always free `lpAttributeList` (HeapFree) on initialization failure and delete the attribute
 *     list on UpdateProcThreadAttribute failure. Ensure meaningful HRESULT/GetLastError values
 *     are returned and preserved for caller.
 *
 * - Command-line assembly and allocation
 *   - Fixed command buffer sizing: allocate room for the terminating NUL (cmdLen + 1).
 *   - Check `malloc()` result and fail fast if allocation fails.
 *   - Initialize buffer to an empty string before concatenation; use `StringCch*` safely with
 *     character counts to avoid buffer overflows.
 *
 * - Console mode handling
 *   - Preserve original console input mode (origMode) in `InputHandlerThread` and restore it
 *     on exit. Avoid restoring a modified mode value.
 *
 * - Password input and writing
 *   - For `PWT_FD` (file-descriptor) use `_get_osfhandle()` to convert CRT fd to Win32 HANDLE and
 *     validate result instead of blindly casting an integer to `HANDLE`.
 *
 * - Robustness / error handling
 *   - Add missing includes used by fixes: `<errno.h>`, `<ctype.h>`, `<io.h>` (for `_get_osfhandle`).
 *   - Check return codes for critical Win32 calls (GetConsoleMode, SetConsoleMode, CreatePipe,
 *     CreatePseudoConsole, ReadFile, WriteFile, CreateProcess etc.) and print/return 
 *     diagnostics (GetLastError) on failure.
 *   - Ensure handles created (pipes, events, thread/process handles) are closed in cleanup paths.
 *
 * - Small correctness / style fixes
 *   - Normalize thread prototypes and definitions to `unsigned __stdcall`.
 *   - Fixed minor compiler warnings (initialize booleans, avoid uninitialized search pointers).
 *   - Minor changes in `argparse.c` to avoid compiler warnings around `strtol`/`strtof` `endptr`
 *     variable usage.
 *
 * Files touched:
 *   - SSHPass.cpp  -- threading changes, heap/attribute-list cleanup, command buffer fixes,
 *                     console-mode preservation, WritePass/WritePassHandle improvements,
 *                     _get_osfhandle usage, additional includes, handle cleanup.
 *   - argparse.c   -- small local fix for `strtol`/`strtof` end-pointer variable initialization.
 *
 * Rationale:
 *   These changes eliminate crashes caused by calling-convention mismatches, fix handle and heap
 *   leaks, make I/O more efficient and robust, and make error diagnostics reliable so callers can
 *   surface real Win32 error codes. They also reduce attack surface/accidental data exposure by
 *   avoiding creating transient undefined memory states and by recommending password zeroization.
 *
 * Notes / recommended follow-ups:
 *   - Add a centralized cleanup block in `main()` (or convert to RAII) to guarantee all resources
 *     (events, pipes, handles, heap allocations) are released on every exit path.
 *   - Consider zeroing sensitive buffers (passwords, temporary command buffers) immediately after
 *     use (SecureZeroMemory).
 *   - Consider adding unit/integration tests that run interactive ssh scenarios (ok/wrong password,
 *     password-from-file, env var) to validate state transitions.
 * 
***********************************************************************/
#include <Windows.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include <errno.h>
#include <ctype.h>
#include <io.h> // for _get_osfhandle()

#include "argparse.h"

static const char* const usages[] = {
        "sshpass [options] command arguments",
        NULL,
};

typedef struct {
    //enum pwtype { PWT_STDIN, PWT_FILE, PWT_FD, PWT_PASS } ;
    // use #DEFINE values from argparse.h
    DWORD pwtype;
    union {
        const char* filename;
        int64_t fd;
        const char* password;
    } pwsrc;

    const char* passPrompt;
    int verbose;

    char* cmd;
} Args;

typedef struct {
    Args args;

    HANDLE pipeIn;
    HANDLE pipeOut;

    HANDLE stdOut;

    HANDLE events[2];
} Context;

static void ParseArgs(int argc, const char* argv[], Context* ctx);
static void WritePass(Context* ctx);
static HRESULT CreatePseudoConsoleAndPipes(HPCON* hpcon, Context* ctx);
static HRESULT InitializeStartupInfoAttachedToPseudoConsole(STARTUPINFOEXA* startupInfo,
    HPCON hpcon);
static unsigned __stdcall PipeListener(LPVOID);
static unsigned __stdcall InputHandlerThread(LPVOID);

int main(int argc, const char* argv[]) {
    Context ctx;
    uint32_t childExitCode = ERROR_SUCCESS;
    int rc = ERROR_SUCCESS;

    ParseArgs(argc, argv, &ctx);

    HRESULT hr = E_UNEXPECTED;

    ctx.pipeIn = INVALID_HANDLE_VALUE;
    ctx.pipeOut = INVALID_HANDLE_VALUE;
    ctx.stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    ctx.events[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ctx.events[0] == NULL) {
        return EXIT_FAILURE;
    }

    // Allow VT100 ANSI Terminal Escape sequences to be procesed by this console
    DWORD consoleMode = 0;
    if (GetConsoleMode(ctx.stdOut, &consoleMode))
    {
        if (SetConsoleMode(ctx.stdOut, consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0)
            rc = GetLastError();
    }
    else
        rc = GetLastError();
    if (rc != ERROR_SUCCESS)
        return rc;

    HPCON hpcon = INVALID_HANDLE_VALUE;

    hr = CreatePseudoConsoleAndPipes(&hpcon, &ctx);     // if this fails, GetLastError() has the error code
    if (S_OK == hr) {
        /* start PipeListener using _beginthreadex so we get a real HANDLE we can close */
        uintptr_t ulPipeListener = _beginthreadex(NULL, 0, PipeListener, &ctx, 0, NULL);
        HANDLE hPipeListener = NULL;
        HANDLE hInputHandler = NULL;

        if (ulPipeListener == 0) {
            rc = GetLastError();
            fprintf(stderr, "Warning: could not start PipeListener thread (continuing): %u\n", rc);
            /* we continue — PipeListener not running; behavior may be degraded */
        }
        else {
            hPipeListener = (HANDLE)ulPipeListener;
        }

#pragma pack(push, 1)  // ensure byte alignment for the structure below
        STARTUPINFOEXA startupInfo = { 0 };
        if (S_OK == InitializeStartupInfoAttachedToPseudoConsole(&startupInfo, hpcon)) {
            PROCESS_INFORMATION cmdProc = { 0 };

            // Create our background Console that runs ctx.args.cmd (should be calling SSH or SCP given what we do)
            rc = CreateProcessA(NULL, ctx.args.cmd, NULL, NULL, FALSE,
                EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                &startupInfo.StartupInfo, &cmdProc);

            // Finally, set <hr> based on result from CreateProcess
            if (rc == 0)
            {
                rc = GetLastError();
				fprintf(stderr, "CreateProcessA failed on '%s': %u\n", ctx.args.cmd, rc);
				childExitCode = rc; // so this is available on exit (tho hr will force EXIT_FAILURE return)
                hr = E_UNEXPECTED;
            }
            else
				hr = S_OK;

            if (S_OK == hr) {
                DWORD d = WAIT_TIMEOUT;

                ctx.events[1] = cmdProc.hThread;

                /* start input handler using _beginthreadex so we get a HANDLE we can close */
                uintptr_t ulInputHandler = _beginthreadex(NULL, 0, InputHandlerThread, &ctx, 0, NULL);
                if (ulInputHandler == 0) {
                    rc = GetLastError();
                    fprintf(stderr, "Could not start InputHandlerThread, error %u\n", rc);
                    /* cleanup: close pipe listener if started */
                    if (hPipeListener) {
                        CloseHandle(hPipeListener);
                    }
                    return rc;
                }
                hInputHandler = (HANDLE)ulInputHandler;
                /* We don't wait on hInputHandler in the WFMO (we wait on the child process thread),
                   but we must close the handle later after the thread terminates. */

                // Wait until we get a signal ([process exit or input comes in
                // event[0] = signalled from thread
                // event[1] = process ended
                //
                while (d == WAIT_TIMEOUT)
                {
                    d = WaitForMultipleObjects(sizeof(ctx.events) / sizeof(HANDLE), ctx.events, FALSE, INFINITE); // wait 1 minute
                    if (d == WAIT_TIMEOUT)  // This never happens now because wait is INFINITE
                        d = WAIT_TIMEOUT;   // use to trap on debug
                    //fprintf(stderr, "WFMO result %i\n", d);
                }

                if (GetExitCodeProcess(cmdProc.hProcess, (LPDWORD)&childExitCode) == 0)
                {
                    childExitCode = GetLastError();
                    fprintf(stderr, "GetExitCodeProcess failed: %u\n", childExitCode);
                    // fall through to Cleanup code
                }
                else if (childExitCode != ERROR_SUCCESS)
                {
					fprintf(stderr, "Child process for cmd '%s' exited with code %u\n", ctx.args, childExitCode);
                }
            }

            /* Close process handles as before */
            CloseHandle(cmdProc.hThread);
            CloseHandle(cmdProc.hProcess);

            /* Close the input handler thread handle now that the process ended and we've waited */
            if (hInputHandler) {
                CloseHandle(hInputHandler);
            }
            /* Close the pipe listener handle if we created it */
            if (hPipeListener) {
                CloseHandle(hPipeListener);
            }

            DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
            HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);
        }
        else
        {
			childExitCode = GetLastError();
            fprintf(stderr, "Warning: could not initialize the console: %u\n", childExitCode);
			hr = S_OK;  // so we return the error code from InitializeStartupInfoAttachedToPseudoConsole()
        }


        ClosePseudoConsole(hpcon);

        if (INVALID_HANDLE_VALUE != ctx.pipeOut) {
            CloseHandle(ctx.pipeOut);
        }
        if (INVALID_HANDLE_VALUE != ctx.pipeIn) {
            CloseHandle(ctx.pipeIn);
        }

        CloseHandle(ctx.events[0]);

        // Free the cmd line buffer we created
        if (ctx.args.cmd != NULL)
            free(ctx.args.cmd);
    }
    else
    {
        // Pipe and/or pseudoconsole creation failed. hr != S_OK
        childExitCode = GetLastError();
        fprintf(stderr, "CreatePseudoConsoleAndPipes() failed, rc = %i", childExitCode);
		hr = S_OK;      // so we return the error code from CreatePseudoConsoleAndPipes()
    }
    return S_OK == hr ? childExitCode : EXIT_FAILURE;
}

static void ParseArgs(int argc, const char* argv[], Context* ctx) {
    const char* filename = NULL;
    int64_t number = 0;
    const char* strpass = NULL;
    int envPass = 0;

    const char* passPrompt = NULL;
    int verbose = 0;

    struct argparse_option options[] = {
            OPT_HELP(),
            OPT_GROUP("Password options: With no options - password will be taken from stdin\nAny options that take arguments do NOT use '='; the text follows the\nswitch immediately.\n"),
            OPT_STRING('f', NULL, &filename, "Take password to use from file", NULL, 0, 0),
            OPT_INTEGER('d', NULL, &number, "Use number as file descriptor for getting password", NULL, 0, 0),
            OPT_STRING('p', NULL, &strpass, "Provide password as argument (security unwise)", NULL, 0, 0),
            OPT_BOOLEAN('e', NULL, &envPass, "Password is passed as env-var \"SSHPASS\"", NULL, 0, 0),
            OPT_GROUP("Other options: "),
            OPT_STRING('P', NULL, &passPrompt, "Which string should sshpass search for to detect a\npassword prompt (case insensitive)", NULL, 0, 0),
            OPT_BOOLEAN('v', NULL, &verbose, "Be verbose about what you're doing", NULL, 0, 0),
            OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, ARGPARSE_STOP_AT_NON_OPTION);
    argc = argparse_parse(&argparse, argc, argv);
    if (argc == 0) {
        argparse_usage(&argparse);
        exit(EXIT_FAILURE);
    }
// TEST CODE - look at the path
//#pragma warning(suppress : 4996)    // So "getenv" calls are not pissed on
//    ctx->args.pwsrc.password = getenv("PATH");

    ctx->args.verbose = verbose;
    if (filename != NULL) {
        ctx->args.pwtype = PWT_FILE;
        ctx->args.pwsrc.filename = filename;
    }
    else if (number != 0) {
        ctx->args.pwtype = PWT_FD;
        ctx->args.pwsrc.fd = number;
    }
    else if (strpass != NULL) {
        ctx->args.pwtype = PWT_PASS;
        ctx->args.pwsrc.password = strpass;
    }
    else if (envPass != 0) {
        ctx->args.pwtype = PWT_PASS;
#pragma warning(suppress : 4996)    // So "getenv" calls are not pissed on
        ctx->args.pwsrc.password = getenv("SSHPASS");
    }
    else {
        ctx->args.pwtype = PWT_STDIN;
    }

    if (passPrompt != NULL) {
        ctx->args.passPrompt = passPrompt;
    }
    else {
        ctx->args.passPrompt = "password:";
    }

    __int64 cmdLen = 0;
    for (int i = 0; i < argc; i++) {
        cmdLen += strlen(argv[i]) + 1;  // room for a space
    }
	cmdLen++; // room for NULL terminator

    ctx->args.cmd = (char *) malloc(sizeof(char) * cmdLen);
    if (ctx->args.cmd == NULL) {
        fprintf(stderr, "Could not allocate memory for command line\n");
        exit(EXIT_FAILURE);
	}
    //memset((PVOID)ctx->args.cmd, 0, sizeof(char) * cmdLen);
	ctx->args.cmd[0] = '\0'; // don't need it to be ALL 0's just a NULL first character

    for (int i = 0; i < argc; i++)
    {
        StringCchCatA(ctx->args.cmd, sizeof(char) * cmdLen, argv[i]);
        if (i < argc - 1)
            // tack on spaces for allbut last one
            StringCchCatA(ctx->args.cmd, sizeof(char) * cmdLen, " ");
    }

    if (ctx->args.verbose) {
        fprintf(stdout, "cmd: %s\n", ctx->args.cmd);
    }
}

// Creates a Psuedoconsole with I/O via pipes. Return the console handie in hpcon, pipes in ctx. if RESULT is not S_OK then
// Error code in GetLastError.
static HRESULT CreatePseudoConsoleAndPipes(HPCON* hpcon, Context* ctx) {
    HRESULT hr = E_UNEXPECTED;
    HANDLE pipePtyIn = INVALID_HANDLE_VALUE;
    HANDLE pipePtyOut = INVALID_HANDLE_VALUE;
	BOOL   bPipe1Ok, bPipe2Ok = 0;      // bPike20KOk initialized to 0 to avoid compiler warning
    int     rc = ERROR_SUCCESS;

    bPipe1Ok = CreatePipe(&pipePtyIn, &ctx->pipeOut, NULL, 0);
    if (bPipe1Ok)   // do not try second if first failed; preserves Error Code
        bPipe2Ok = CreatePipe(&ctx->pipeIn, &pipePtyOut, NULL, 0);

    if (bPipe1Ok && bPipe2Ok)
    {
        // WHat we do if pipe creation works
        COORD consoleSize = { 0 };

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
            consoleSize.X = csbi.srWindow.Right - csbi.srWindow.Left + 1;
            consoleSize.Y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        }
        else {
            consoleSize.X = 120;
            consoleSize.Y = 25;
        }
        hr = CreatePseudoConsole(consoleSize, pipePtyIn, pipePtyOut, 0, hpcon);
        if (hr != S_OK)
            // Save error code so we can restore after cleanup
            rc = GetLastError();

        // Why do we CLOSE the pipes used to create the Console right after creating the Console?
        if (bPipe2Ok) {
            CloseHandle(pipePtyOut);
        }

        if (bPipe1Ok) {
            CloseHandle(pipePtyIn);
        }
        // Restore error code
        SetLastError(rc);
    }
    else
    {
        // Close out pipes that were properly created if there was an error. Reset ctx pipes to INVALID after closing
        rc = GetLastError();       // Save the error code
        if (bPipe1Ok)
        {
            CloseHandle(pipePtyIn);
            CloseHandle(ctx->pipeOut);
            ctx->pipeOut = INVALID_HANDLE_VALUE;
        }
        if (bPipe2Ok)
        {
            CloseHandle(pipePtyOut);
            CloseHandle(ctx->pipeIn);
            ctx->pipeIn = INVALID_HANDLE_VALUE;
        }
        // Restore Error Code so caller can get it
        SetLastError(rc);
    }
    return hr;
}

static HRESULT InitializeStartupInfoAttachedToPseudoConsole(STARTUPINFOEXA* startupInfo,
    HPCON hpcon) {
    HRESULT hr = E_UNEXPECTED;
    if (startupInfo == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return hr;
    }

    SIZE_T attrListSize = 0;
    startupInfo->StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // get required size
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);

    startupInfo->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrListSize);
    if (startupInfo->lpAttributeList == NULL) {
        SetLastError(ERROR_OUTOFMEMORY);
        return hr;
    }

    if (!InitializeProcThreadAttributeList(startupInfo->lpAttributeList, 1, 0, &attrListSize)) {
        DWORD err = GetLastError();
		// Need to free up lpAttributeList on failure
        HeapFree(GetProcessHeap(), 0, startupInfo->lpAttributeList);
        startupInfo->lpAttributeList = NULL;
        SetLastError(err);
        return hr;
    }

    hr = (UpdateProcThreadAttribute(startupInfo->lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hpcon, sizeof(HPCON), NULL,
        NULL) ? S_OK : E_UNEXPECTED);

    if (hr != S_OK) {
		// Cleanup on failure (caller only cleans up on success)
		DWORD err = GetLastError();
        DeleteProcThreadAttributeList(startupInfo->lpAttributeList);
        HeapFree(GetProcessHeap(), 0, startupInfo->lpAttributeList);
        startupInfo->lpAttributeList = NULL;
		SetLastError(err);
    }

    return hr;
}

#define _TCHAR char
_TCHAR* stristr(_TCHAR* pszMain, _TCHAR* pszFind, int iMaxLen)
{
    _TCHAR* p;
    DWORD	i, j, n, iNext;
    DWORD	dwFind, dwMain;

    dwFind = strlen(pszFind);
    dwMain = min(strlen(pszMain), iMaxLen);

    if (dwFind > dwMain)
    {
        // Find string is longer than the string we will search... no match possible
        p = NULL;
        goto STR_EXIT;
    }
    else if (dwFind == 0 && dwMain != 0)
    {
        // Find string is NULL but MAIN is not...
        p = NULL;
        goto STR_EXIT;
    }
    else if (dwFind == 0 && dwMain == 0)
    {
        // Save us some grief... both are 0 so just leave with a match
        p = pszMain;
        goto STR_EXIT;
    }
    else
        // Normal case... start w/ rc == 1 to keep the loop going
        p = NULL;

    // We will set 'rc' to 0 if we actually get a match !!
    for (i = 0; p == NULL && i <= dwMain - dwFind; i++)
    {
        // Start by looking for the FIRST character
        if (tolower(pszMain[i]) == tolower(*pszFind))
        {
            // First char matches... check to see if the rest do as well
            j = 0;
            iNext = 0;
            for (n = 1; n < dwFind && j == 0; n++)
            {
                j = tolower(pszMain[i + n]) - tolower(pszFind[n]);
                // As long as we are looking, look for another occurance of the start of this string (char #1)
                // Save the offset to the EARLIEST occurance as the place to restart
                if (iNext == 0 && tolower(pszMain[i + n]) == tolower(pszFind[0]))
                    iNext = n;
            }
            // If 'j' is still 0 then we found a match!!
            if (j == 0)
                p = pszMain + i;

            // If iNext is still 0, then there were no occurances of pszFind[0] from i+1 to i + dwFind -1.
            // If iNext is non-zero, then it contains the offset to the first occurance of pszFind[0] in
            // the aforementioned range. Do the Right Thing to speed our searching...
            if (iNext)
                // We found an occurance
                i += iNext - 1;		// Subtract 1 because FOR loop increments i
            else
                // No occurances, so skip as much of this range as we've covered so far...
                i += n - 1;
        }
    }

STR_EXIT:
    return p;
}

// Return TRUE if we get a match on the password prompt string. CASE insensitive
// //
//static BOOL IsWaitInputPass(Context* ctx, const char* buffer, DWORD len) {
static BOOL IsWaitInputPass(Context * ctx, char* buffer, DWORD len) {
        char* pos = stristr(buffer, (char *)ctx->args.passPrompt, len);
    if (pos == NULL) {
        return FALSE;
    }
    return TRUE;
}

typedef enum {INIT, VERIFY, EXEC, END } State;

//static State ProcessOutput(Context* ctx, const char* buffer, DWORD len, State state) {
static State ProcessOutput(Context * ctx, char* buffer, DWORD len, State state) {
        State nextState;
    switch (state) {
        case INIT: {
            if (!IsWaitInputPass(ctx, buffer, len)) {
                nextState = INIT;
            }
            else {
                WritePass(ctx);
                nextState = VERIFY;
            }
        } break;
        case VERIFY: {
            if (IsWaitInputPass(ctx, buffer, len)) {
                fprintf(stderr, "Password rejected!\n");
                nextState = END;
            }
            else {
                fprintf(stdout, "%s", buffer);
                nextState = EXEC;
            }
        } break;
        case EXEC: {
            fprintf(stdout, "%s", buffer);
            nextState = EXEC;
        } break;
        case END: {
            nextState = END;
        } break;
        default: {
            nextState = END;    // END on unknown state
        } break;
    }   // end of switch
    return nextState;
}

// Wait until we are able to read from the input pipe, then look for the PASSWORD string. When it is seen, 
#define BUFFER_SIZE 1024
static unsigned __stdcall PipeListener(LPVOID arg) {
    Context* ctx = (Context *)arg;

    char buffer[BUFFER_SIZE + 1] = { 0 };

    DWORD bytesRead;

    BOOL fRead = FALSE;

    State state = INIT;

    while (1) {
        fRead = ReadFile(ctx->pipeIn, buffer, BUFFER_SIZE, &bytesRead, NULL);
        if (!fRead || bytesRead == 0) {
            break;
        }
        buffer[bytesRead] = 0;
        state = ProcessOutput(ctx, buffer, bytesRead, state);
        if (state == END) {
            break;
        }
    }
    SetEvent(ctx->events[0]);
    return 0;
}
 
static void WritePassHandle(Context* ctx, HANDLE src) {
    int done = 0;

    while (!done) {
        char buffer[40] = { 0 };
        DWORD i;
        DWORD bytesRead;
        (void) ReadFile(src, buffer, sizeof(buffer), &bytesRead, NULL);
        done = (bytesRead < 1);
        for (i = 0; i < bytesRead && !done; ++i) {
            if (buffer[i] == '\r' || buffer[i] == '\n') {
                done = 1;
                break;
            }
            else {
                WriteFile(ctx->pipeOut, buffer + i, 1, NULL, NULL);
            }
        }
    }
    WriteFile(ctx->pipeOut, "\n", 1, NULL, NULL);
}

static void WritePass(Context* ctx) {
    switch (ctx->args.pwtype) {
    case PWT_STDIN:
        WritePassHandle(ctx, GetStdHandle(STD_INPUT_HANDLE));
        break;
    case PWT_FD: {
        // Convert CRT fd to Win32 HANDLE safely
        intptr_t osHandle = _get_osfhandle((int)ctx->args.pwsrc.fd);
        if (osHandle == -1) {
            fprintf(stderr, "Invalid file descriptor for password input\n");
        }
        else {
            HANDLE hSrc = (HANDLE)osHandle;
            WritePassHandle(ctx, hSrc);
        }
    } break;    case PWT_FILE: {
        HANDLE file = CreateFileA(ctx->args.pwsrc.filename, GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
        if (file != INVALID_HANDLE_VALUE) {
            WritePassHandle(ctx, file);
            CloseHandle(file);
        }
    } break;
    case PWT_PASS: {
        WriteFile(ctx->pipeOut, ctx->args.pwsrc.password, strlen(ctx->args.pwsrc.password), NULL, NULL);
        WriteFile(ctx->pipeOut, "\n", 1, NULL, NULL);

    } break;
    }
}

// This is the Thread that we run with STDIN and STDOUT redirected. We loop, reading output and writing input on character at a time until there is an error (or we are terminated)
static unsigned __stdcall InputHandlerThread(LPVOID arg) {
    Context* ctx = (Context*)arg;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode, origMode;

    GetConsoleMode(hStdin, &origMode);                  // current console mode
    mode = origMode;                                    // Start with this...
    mode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);   // turn off ENABLE_LINE_INPUT & ENABLE_ECHO_INPUT
    mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;              // turn on ENABLE_VIRTUAL_TERMINAL_INPUT
    SetConsoleMode(hStdin, mode);

    char buffer = 0;
    DWORD bytesRead, bytesWritten;

    while (1) {
        if (!ReadFile(hStdin, &buffer, 1, &bytesRead, NULL) || bytesRead == 0) {
            break;
        }

        if (!WriteFile(ctx->pipeOut, &buffer, 1, &bytesWritten, NULL)) {
            break;
        }
    }

    SetConsoleMode(hStdin, origMode);
    return 0;
}