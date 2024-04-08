// ReSharper disable CppClangTidyClangDiagnosticC2xExtensions
#include <Windows.h>
#include <stdio.h>

#define TO_STRING(STR) #STR

static const char *ProcessAccessString[] = {
    TO_STRING(PROCESS_TERMINATE),
    TO_STRING(PROCESS_CREATE_THREAD),
    TO_STRING(PROCESS_SET_SESSIONID),
    TO_STRING(PROCESS_VM_OPERATION),
    TO_STRING(PROCESS_VM_READ),
    TO_STRING(PROCESS_VM_WRITE),
    TO_STRING(PROCESS_DUP_HANDLE),
    TO_STRING(PROCESS_CREATE_PROCESS),
    TO_STRING(PROCESS_SET_QUOTA),
    TO_STRING(PROCESS_SET_INFORMATION),
    TO_STRING(PROCESS_QUERY_INFORMATION),
    TO_STRING(PROCESS_SUSPEND_RESUME),
    TO_STRING(PROCESS_QUERY_LIMITED_INFORMATION),
    TO_STRING(PROCESS_SET_LIMITED_INFORMATION)};

static const char *ThreadAccessString[] = {
    TO_STRING(THREAD_TERMINATE),
    TO_STRING(THREAD_SUSPEND_RESUME),
    TO_STRING(THREAD_GET_CONTEXT),
    TO_STRING(THREAD_SET_CONTEXT),
    TO_STRING(THREAD_SET_CONTEXT),
    TO_STRING(THREAD_SET_INFORMATION),
    TO_STRING(THREAD_QUERY_INFORMATION),
    TO_STRING(THREAD_SET_THREAD_TOKEN),
    TO_STRING(THREAD_IMPERSONATE),
    TO_STRING(THREAD_DIRECT_IMPERSONATION),
    TO_STRING(THREAD_SET_LIMITED_INFORMATION),
    TO_STRING(THREAD_QUERY_INFORMATION),
    TO_STRING(THREAD_QUERY_LIMITED_INFORMATION),
    TO_STRING(THREAD_RESUME)};

static const DWORD ProcessAccessValues[] = {PROCESS_TERMINATE,
                                            PROCESS_CREATE_THREAD,
                                            PROCESS_SET_SESSIONID,
                                            PROCESS_VM_OPERATION,
                                            PROCESS_VM_READ,
                                            PROCESS_VM_WRITE,
                                            PROCESS_DUP_HANDLE,
                                            PROCESS_CREATE_PROCESS,
                                            PROCESS_SET_QUOTA,
                                            PROCESS_SET_INFORMATION,
                                            PROCESS_QUERY_INFORMATION,
                                            PROCESS_SUSPEND_RESUME,
                                            PROCESS_QUERY_LIMITED_INFORMATION,
                                            PROCESS_SET_LIMITED_INFORMATION};

static const DWORD ThreadAccessValues[] = {THREAD_TERMINATE,
                                           THREAD_SUSPEND_RESUME,
                                           THREAD_GET_CONTEXT,
                                           THREAD_SET_CONTEXT,
                                           THREAD_SET_CONTEXT,
                                           THREAD_SET_INFORMATION,
                                           THREAD_QUERY_INFORMATION,
                                           THREAD_SET_THREAD_TOKEN,
                                           THREAD_IMPERSONATE,
                                           THREAD_DIRECT_IMPERSONATION,
                                           THREAD_SET_LIMITED_INFORMATION,
                                           THREAD_QUERY_INFORMATION,
                                           THREAD_QUERY_LIMITED_INFORMATION,
                                           THREAD_RESUME};

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: <PID> <TID>\n");
    return 0;
  }

  const DWORD ProcessId = strtol(argv[1], NULL, 10);
  const DWORD ThreadId = strtol(argv[2], NULL, 10);

  BOOL AllowedProcessAccess[ARRAYSIZE(ProcessAccessValues)] = {};
  BOOL AllowedThreadAccess[ARRAYSIZE(ThreadAccessValues)] = {};
  BOOL CanAccessProcess = FALSE;

  for (SIZE_T I = 0; I < ARRAYSIZE(ProcessAccessValues); I++) {
    const HANDLE Handle = OpenProcess(ProcessAccessValues[I], FALSE, ProcessId);
    if (Handle != NULL) {
      AllowedProcessAccess[I] = TRUE;
      CanAccessProcess = TRUE;
      CloseHandle(Handle);
    }
  }

  if (!CanAccessProcess) {
    fprintf(stdout, "No access to process.\n");
    return 0;
  }

  for (SIZE_T I = 0; I < ARRAYSIZE(ThreadAccessValues); I++) {
    const HANDLE ThreadHandle =
        OpenThread(ThreadAccessValues[I], FALSE, ThreadId);

    if (ThreadHandle != NULL) {
      AllowedThreadAccess[I] = TRUE;
      CloseHandle(ThreadHandle);
    }
  }

  fprintf(stdout, "AllowedProcessAccess\n");

  for (SIZE_T I = 0; I < ARRAYSIZE(AllowedProcessAccess); I++) {
    if (AllowedProcessAccess[I]) {
      fprintf(stdout, "\t%s\n", ProcessAccessString[I]);
    }
  }

  fprintf(stdout, "AllowedThreadAccess\n");

  for (SIZE_T I = 0; I < ARRAYSIZE(AllowedThreadAccess); I++) {
    if (AllowedThreadAccess[I]) {
      fprintf(stdout, "\t%s\n", ThreadAccessString[I]);
    }
  }

  return 0;
}
