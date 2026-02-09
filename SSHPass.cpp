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
* Crunched codebase with CoPoilot, found several issues and fixed them. Also added a bunch of comments to help me remember how this works. CoPilot-assisted changes:
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
 * 
 * v2.0.4.0  2/5/2026
 * Added an error message in main() to indicate the PipeListener event could not be created (vs. silent exit).
 * 
 * v2.1.0.0  2/9/26
 * Added -c / --CtrlC switch to allow users to specify whether Ctrl-C should be handled locally by SSHPass (and not sent to the server process) or whether Ctrl-C
 * should be sent to the server process. This is important because if the user wants to handle Ctrl-C locally, we capture the Ctrl-C and shutdown gracefully.
 * If Ctrl-C is sent to the server process, we rely on the server-side to handle it and keep going or exit so we can shutdown gracefully. Also tweaked exit
 * code and created CloseInputHandler() to do our best to let the InputHandler thread exit gracefully and restore the console state before exit. Not guaranteeed,
 * but much better than previous version.
 * 
 * Commented/if'd out the code for argparse_describe(). It was not being used; code is still there if one wants to use it going forward...
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
    int ctrlCType;

    char* cmd;
} Args;

// Our Context Structure use to pass info around amongst threads and such
typedef struct {
	Args args;          // Arguments parsed from the command line

	HANDLE pipeIn;      // Handle for the input side of the pipe we create to talk to the PseudoConsole
	HANDLE pipeOut;     // Handle for the output side of the pipe we create to talk to the PseudoConsole. We keep this around so we can close it to cause the InputHandler thread to exit when we want to shutdown.

	HANDLE stdOut;      // Handle for the real STDOUT of the process, used to modify console modes and such

	HANDLE events[3];   // Event handles used for signalling: [0] = PipeListener quitting Event, [1] = Process we launched has exited - this is the process handle, [2] = Ctrl-C pressed Event
	DWORD  cEvents;     // Count of "active" events in the array above   
} Context;

static void ParseArgs(int argc, const char* argv[], Context* ctx);
static void WritePass(Context* ctx);
static HRESULT CreatePseudoConsoleAndPipes(HPCON* hpcon, Context* ctx);
static HRESULT InitializeStartupInfoAttachedToPseudoConsole(STARTUPINFOEXA* startupInfo,
    HPCON hpcon);
static unsigned __stdcall PipeListener(LPVOID);
static unsigned __stdcall InputHandlerThread(LPVOID);

// global pointer to the Context for the console control handler. We need this because the handler only gets the control type otherwiseand has no way to get a pointer to our Context
static Context* g_ctrlCtx = NULL;

// index into ctx->events[] for the Ctrl-C event (if installed). We need this because the handler needs to know which event to signal when Ctrl-C is pressed. MUST BE THE LAST EVENT IN THE ARRAY
static const int CTRL_C_EVENT_INDEX = 2;

// Ctrl-C Handler code; only installed IF REQUIRED. Signals the main thread using ctx.events[2]. Return TRUE if we handle Ctrl-C (so System does not take over), FALSE if not.
static BOOL WINAPI CtrlConsoleHandler(DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        // Signal the shutdown event stored in ctx.events[CTRL_C_EVENT_INDEX] (must be created by main)
        if (g_ctrlCtx != NULL && g_ctrlCtx->events[CTRL_C_EVENT_INDEX] != NULL) {
            SetEvent(g_ctrlCtx->events[CTRL_C_EVENT_INDEX]);
            return TRUE; // we handled it
        }
    }
    return FALSE; // not handled
}

// Install the console control handler and create ctx.events[2].
// Returns TRUE on success. Caller should check return and proceed even if it fails.
static BOOL InstallCtrlCHandler(Context* ctx)
{
    if (ctx == NULL)
        return FALSE;

    // Create shutdown event if not already present
    if (ctx->events[CTRL_C_EVENT_INDEX] == NULL) {
        ctx->events[CTRL_C_EVENT_INDEX] = CreateEvent(NULL, TRUE, FALSE, NULL); // manual-reset, initially not signaled
        if (ctx->events[CTRL_C_EVENT_INDEX] == NULL) {
            return FALSE;
        }
    }

    // Make handler see our ctx. MUST DO THIS before we set the handler!
    g_ctrlCtx = ctx;
    // Update active event count to include the shutdown event (events[0] and events[1] already present)
    ctx->cEvents = CTRL_C_EVENT_INDEX + 1;

    // Register handler
    if (!SetConsoleCtrlHandler(CtrlConsoleHandler, TRUE)) {
        CloseHandle(ctx->events[CTRL_C_EVENT_INDEX]);
        ctx->events[CTRL_C_EVENT_INDEX] = NULL;
		ctx->cEvents = CTRL_C_EVENT_INDEX;  // update event count to reflect that shutdown event is not active
		g_ctrlCtx = NULL;                   // don't need this either
        return FALSE;
    }
    return TRUE;
}

// Uninstall the console control handler and destroy ctx.events[2].
// Safe to call even if Install failed/was not called.
static void UninstallCtrlCHandler(Context* ctx)
{
    if (ctx == NULL)
        return;

    // Remove handler (ignore return)
    SetConsoleCtrlHandler(CtrlConsoleHandler, FALSE);

    // Clear global pointer so handler won't touch ctx after uninstall
    g_ctrlCtx = NULL;

    // Close and clear shutdown event if present
    if (ctx->events[CTRL_C_EVENT_INDEX] != NULL) {
        CloseHandle(ctx->events[CTRL_C_EVENT_INDEX]);
        ctx->events[CTRL_C_EVENT_INDEX] = NULL;
    }

    // Restore event count (events[0] + events[1])
    ctx->cEvents = CTRL_C_EVENT_INDEX;
}

// Helper function to close the input handler thread and its associated event handle. Should be called from the main thread after the PipeListener has quit OR the process we launched has exited.
// Need to ensure the Input Handler closes so the console can be properly restored by it. WE DO NOT close hInputHandler (but we may close and so mark ctx->pipeOut as part of forcing InputHandler to exit).
//
// ctx: pointer to the Context structure with all sorts of goodies
// hInputHandler: the HANDLE for the Input Handler thread that we want to close
// returns: ERRRO_SUCCESS else error code. STRONGLY SUGGEST that this error simply be reported and that the caller does their best to continue with shutdown...
//
static DWORD CloseInputHandler(Context* ctx, HANDLE hInputHandler)
{
    DWORD rc = ERROR_SUCCESS;
    if (hInputHandler != NULL) {
        // Close ctx->pipeOut so that InputHandler's Write calls will fail and cause it to exit... once we unblock the ReadFile by cancelling Sync IO for the thread
        if (ctx->pipeOut != INVALID_HANDLE_VALUE)
        {
            CloseHandle(ctx->pipeOut);
            ctx->pipeOut = INVALID_HANDLE_VALUE;
        }
        // Now cancel the synch IO for the thread
        if (!CancelSynchronousIo(hInputHandler))
        {
            // Well that did not work
            rc = GetLastError();
            fprintf(stderr, "Warning: could not cause InputHandler thread to exit gracefully: %u\n", rc);
        }
        else
        {
            // Ok now that we have nuked the ReadFile and we know WriteFile will fail, we wait for the thread to exit
            DWORD wait = WaitForSingleObject(hInputHandler, 2000); // 2s grace
            if (wait != WAIT_OBJECT_0) {
                // last resort: wait a bit longer or close handle anyway
                wait = WaitForSingleObject(hInputHandler, 2000);
            }
            if (wait != WAIT_OBJECT_0)
                // well that did not work either. We are really in a bad state at this point because the thread is still running but we have closed the handle to it, so we cannot wait on it anymore or close it cleanly. 
                fprintf(stderr, "Warning: InputHandler thread did not exit cleanly, your console behavior could be wonky...\n");
        }
    }
	return rc;
}

// Entry point for the program. Parses command line arguments, sets up the pseudo console and pipes, starts the listener and input handler threads, and waits for the child process to exit before cleaning up and 
// returning the child's exit code (or an error code if something went wrong). May also return EXIT_FAILURE vs a specific Win32 error code.
int main(int argc, const char* argv[]) {
    Context ctx = { 0 };                            // keep compiler happy
    uint32_t childExitCode = ERROR_SUCCESS;
    int rc = ERROR_SUCCESS;

    ctx.pipeIn = INVALID_HANDLE_VALUE;              // these will be created shortly
    ctx.pipeOut = INVALID_HANDLE_VALUE;
    ctx.stdOut = GetStdHandle(STD_OUTPUT_HANDLE);   // used to modify the status of the launching console.

    ParseArgs(argc, argv, &ctx);

    HRESULT hr = E_UNEXPECTED;

    // This event will be used by the PipeListener thread to signal us that it is quitting...
    ctx.events[ctx.cEvents] = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ctx.events[ctx.cEvents] == NULL) {
		fprintf(stderr, "Could not create input thread event: %u\n", GetLastError());
        return EXIT_FAILURE;
    }
    ctx.cEvents++;      // track this event

    HPCON hpcon = INVALID_HANDLE_VALUE;     // this is the PseudoConsole handle

	// Create an input and output handle for the PseudoConsole (in <ctx>), and create the PseudoConsole itself; handle returned in hpcon.
    hr = CreatePseudoConsoleAndPipes(&hpcon, &ctx);     // if this fails, GetLastError() has the error code
    if (S_OK == hr) {
		// Start PipeListener using _beginthreadex so we get a real HANDLE we can close. This thread will set ctx.events[0] when it is quitting
        // so we can respond to that and do a clean shutdown.
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
		// Force startupInfo to be bound to the PseudoConsole created above <hpcon>. This is necessary for the child process we create to be attached to that console 
        // and have its I/O redirected to the pipes we created.
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

				ctx.events[ctx.cEvents] = cmdProc.hThread;      // the process thread handle; used for WaitForMultipleObjects
                ctx.cEvents++;

                // Start input handler using _beginthreadex so we get a HANDLE we can close. This call, if successful, also starts mucking with Console settings (we
				// want to ensure this thread exits cleanly so that it can restore the console settings on its way out -- see CloseInputHandler().
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

                // Do we need the Ctrl-C handler? If so, enable it. DO NOT fail if this fails
                if (ctx.args.ctrlCType == CTRLC_LOCAL) {
                    if (!InstallCtrlCHandler(&ctx)) {
                        fprintf(stderr, "Warning: could not install Ctrl-C handler: %u\n", GetLastError());
                        // continue — graceful shutdown still attempted via other paths
                    }
                }

                // Wait until we get a signal ([process exit or input comes in
                // event[0] = signalled from thread
                // event[1] = process ended
				// event[2] = Ctrl-C pressed (if we installed the handler)
                //
                while (d == WAIT_TIMEOUT)
                {
					// Event 0 comes from PipeListener thread - signals it is ending. Event 1 comes from the child process thread (e.g. SSH or SCP) - signals it is ending. 
                    // Either way we are quitting...
                    d = WaitForMultipleObjects(ctx.cEvents, ctx.events, FALSE, INFINITE); // wait 1 minute
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
					fprintf(stderr, "Child process for cmd '%s' exited with code %u\n", ctx.args.cmd, childExitCode);
                }
            }
            // Try to ensure a clean exit by InputHandler which restores our console state... DO NOT fail at this point if we cannot make this happen (reported by CloseInputHandler()) because we want the
            // rest of our shutdown code to run.
			rc = CloseInputHandler(&ctx, hInputHandler);

            /* Close process handles as before */
            CloseHandle(cmdProc.hThread);
            CloseHandle(cmdProc.hProcess);

			// Uninstall Ctrl-C handler if we installed it
            if (ctx.args.ctrlCType == CTRLC_LOCAL) {
                UninstallCtrlCHandler(&ctx);
            }
            /* Close the input handler thread handle now that the process ended and we've waited */
            if (hInputHandler) {
                CloseHandle(hInputHandler);
            }
            /* Close the pipe listener handle if we created it */
            if (hPipeListener) {
                CloseHandle(hPipeListener);
            }
            if (startupInfo.lpAttributeList != NULL)
            {
				// Delete and Free the Attribute List we created
                DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
                HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);
            }
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
    const char* ctrlc = NULL;

    struct argparse_option options[] = {
            OPT_HELP(),
            OPT_GROUP("Password options: With no options - password will be taken from stdin\nAny options that take arguments do NOT use '='; the text follows the\nswitch immediately.\n"),
            OPT_STRING('f', NULL, &filename, "Take password to use from file", NULL, 0, 0),
            OPT_INTEGER('d', NULL, &number, "Use number as file descriptor for getting password", NULL, 0, 0),
            OPT_STRING('p', NULL, &strpass, "Provide password as argument (security unwise)", NULL, 0, 0),
            OPT_BOOLEAN('e', NULL, &envPass, "Password is passed as env-var \"SSHPASS\"", NULL, 0, 0),
            OPT_GROUP("Other options: "),
            OPT_STRING('P', NULL, &passPrompt, "Which string should sshpass search for to detect a password prompt (case insensitive; default is \"password:\")", NULL, 0, 0),
            OPT_BOOLEAN('v', NULL, &verbose, "Be verbose about what you're doing", NULL, 0, 0),
            OPT_STRING('c', "ctrlc", &ctrlc, "Where to handle Ctrl-C; either \"local\" (Ctrl-C handled by this process) or \"server\" (Default; Ctrl-C sent to server process)", NULL, 0, 0),
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

    if (ctrlc != NULL) {
        if (_stricmp(ctrlc, "local") == 0) {
            ctx->args.ctrlCType = CTRLC_LOCAL; // local
        }
        else if (_stricmp(ctrlc, "server") == 0) {
            ctx->args.ctrlCType = CTRLC_SERVER; // server
        }
        else {
            fprintf(stderr, "Invalid value for -c option: %s\n", ctrlc);
            exit(EXIT_FAILURE);
        }
    }
    else {
        ctx->args.ctrlCType = CTRLC_SERVER; // default is Server
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
// hpcon is the handle to the new console
// ctx is the context struct where we will put the handles for the pipes we create to talk to that console. The pipes passed to
//        the pseudoconsole are tied to these and "owned" by the pseudoconsole (which is why we close our values of those handles right after creating the console.
//        The console keeps them alive/owns them and we use the ctx versions to talk to the console). Odd but that is how it works.
// We return an HRESULT so we can return failure without losing the GetLastError() code which may be important to the caller.
// 
static HRESULT CreatePseudoConsoleAndPipes(HPCON* hpcon, Context* ctx) {
    HRESULT hr = E_UNEXPECTED;
    HANDLE pipePtyIn = INVALID_HANDLE_VALUE;
    HANDLE pipePtyOut = INVALID_HANDLE_VALUE;
	BOOL   bPipe1Ok, bPipe2Ok = 0;      // bPike20KOk initialized to 0 to avoid compiler warning
    int     rc = ERROR_SUCCESS;

    // Must create 2 sets of pipes (if we used ctx->pipeOut and pipePtyIn, everything we send to pipePtyIn would come right back out via ctx-PipeOut. We will
    // discard the pipePtyIn (and pipePtyOut) handle before exiting; these will be STDIN and STDOUT/STDERR for the PsuedoConsole. ctx will have the other handles.
	// cts->pipeIn is STDOUT/STDERR for the console (read data), ctx->pipeOut is STDIN for the console (write data).
    bPipe1Ok = CreatePipe(&pipePtyIn, &ctx->pipeOut, NULL, 0);
    if (bPipe1Ok)   // do not try second if first failed; preserves Error Code
        bPipe2Ok = CreatePipe(&ctx->pipeIn, &pipePtyOut, NULL, 0);

    if (bPipe1Ok && bPipe2Ok)
    {
		// Need screen and buffer size to create the console. Get them from the current console, but if that fails use defaults of 120x25
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
		// Now create the pseudoconsole with its pipes; handle we use returned in hpcon (which is a POINTER to a handle). 
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

// Tie the Attribute List in startupInfo to the PseudoConsole we created so that when we do create a process with startupInfo, it is attached to that console and 
// has its I/O redirected to the pipes we created. If RESULT is not S_OK then call GetLastError() for the error code.
//
// If successful, the caller must call HeapFree() on startupInfo->lpAttributeList after calling DeleteProcThreadAttributeList() on it. 
// If we fail, we free it here because the caller will not be expecting to have to clean up anything on failure.
//
static HRESULT InitializeStartupInfoAttachedToPseudoConsole(STARTUPINFOEXA* startupInfo, HPCON hpcon)
{
    HRESULT hr = E_UNEXPECTED;
    if (startupInfo == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return hr;
    }

    SIZE_T attrListSize = 0;
    startupInfo->StartupInfo.cb = sizeof(STARTUPINFOEXA);

	// get required size for an attribute list with 1 attribute 
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    // Allocate the buffer
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
	// Attach the PseudoConsole to the attribute list so that it will be used when we create the child process with this startupInfo
    hr = (UpdateProcThreadAttribute(startupInfo->lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hpcon, sizeof(HPCON), NULL,
        NULL) ? S_OK : E_UNEXPECTED);

    if (hr != S_OK) {
		// Cleanup on failure (caller only cleans up on success). These are the same steps caller will need to take to clean things up (Delete List, Free List).
		DWORD err = GetLastError();
        DeleteProcThreadAttributeList(startupInfo->lpAttributeList);
        HeapFree(GetProcessHeap(), 0, startupInfo->lpAttributeList);
        startupInfo->lpAttributeList = NULL;
		SetLastError(err);
    }

    return hr;
}

#define _TCHAR char
_TCHAR* stristr(_TCHAR* pszMain, _TCHAR* pszFind, DWORD dMaxLen)
{
    _TCHAR* p;
    DWORD	i, j, n, iNext;
    DWORD	dwFind, dwMain;

	// Use static_cast to avoid compiler warnings about truncation - not worried about strings > 4GB in length
    dwFind = static_cast<DWORD>(strlen(pszFind) );
    dwMain = min(static_cast<DWORD>(strlen(pszMain) ), dMaxLen);

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

// State-based output processing
// //
// ctx = context info for psuedoconsole (PS) process
// buffer = PS process output to be processed
// len = length of buffer
// state = current state of the state machine
// 
// RETURNS: new state value
// 
// When state is INIT we look for the password prompt. When we see it, we write the password and move to VERIFY. 
// In VERIFY we look to see if we get the prompt again (which would indicate a bad password) or if we get something else (which would indicate the password was 
// accepted and we are now getting normal output). If we get the prompt again, we print "Password rejected" and move to END. If we get something else, we print 
// it and move to EXEC. In EXEC, we just print everything that comes in until the pipe is closed
//
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

// Wait until we are able to read from the input pipe, then process data as it comes in with ProcessOutput(). 
// Runs in its own thread. Signals through ctx->events[0] when we are done processing (either process ended or we got a password failure and are exiting).
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
			// End loop on error or if the pipe is closing (0 bytes read)
            break;
        }
		buffer[bytesRead] = '\0'; // Null terminate the buffer so we can treat it as a string
		// State-machine based processing of the output. Handles password entry/verification and supsequent output from the process
        state = ProcessOutput(ctx, buffer, bytesRead, state);
        if (state == END) {
            break;
        }
    }
	// Signal main thread that we are done processing output (either process ended or we got a password failure and are exiting)
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
        WriteFile(ctx->pipeOut, ctx->args.pwsrc.password, static_cast<DWORD>(strlen(ctx->args.pwsrc.password) ), NULL, NULL);
        WriteFile(ctx->pipeOut, "\n", 1, NULL, NULL);

    } break;
    }
}

// This is the Thread that we run to manage PseudoConsole (PS) input. It waits for input on the console where we launched sshpass, then writes that input to the PS input pipe 
// so it gets to the process we are running in the PS (e.g. SSH or SCP).
// argument is a pointer to our Context struct 
static unsigned __stdcall InputHandlerThread(LPVOID arg) {
    Context* ctx = (Context*)arg;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode, origMode;

    // Set the PS to the mode we want...
    GetConsoleMode(hStdin, &origMode);                  // current console mode
    mode = origMode;                                    // Start with this...
    mode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);   // turn off ENABLE_LINE_INPUT & ENABLE_ECHO_INPUT
    if (ctx->args.ctrlCType == CTRLC_LOCAL)
        mode |= ENABLE_PROCESSED_INPUT;                 // turn on ENABLE_PROCESSED_INPUT
    else
        mode &= ~ENABLE_PROCESSED_INPUT;                // turn off ENABLE_PROCESSED_INPUT
	
    // Allow VT100 ANSI Terminal Escape sequences to be procesed by this console
    mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;              // turn on ENABLE_VIRTUAL_TERMINAL_INPUT
    SetConsoleMode(hStdin, mode);

    char buffer = 0;
    DWORD bytesRead, bytesWritten;

	// Get each keystroke from the main console window and write it to the PS for processing. This allows the user to interact with the PS process (e.g. SSH or SCP) as if they were directly at a console for that process. 
    // We keep doing this until we get an error or 0 bytes read which indicates the console input is closing (e.g. user pressed Ctrl+Z or closed the window). We do NOT report read or write errors here.
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