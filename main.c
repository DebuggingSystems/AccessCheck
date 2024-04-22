// ReSharper disable CppClangTidyClangDiagnosticC2xExtensions
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <Windows.h>

#define TO_STRING(STR) #STR

static const char * const ProcessAccessString[] = {
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

static const char * const ThreadAccessString[] = {
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

static const uint32_t ProcessAccessValues[] = {PROCESS_TERMINATE,
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

static const uint32_t ThreadAccessValues[] = {THREAD_TERMINATE,
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

  const uint32_t process_id = strtol(argv[1], NULL, 10);
  const uint32_t thread_id = strtol(argv[2], NULL, 10);

  bool allowed_process_access[ARRAYSIZE(ProcessAccessValues)] = {};
  bool allowed_thread_access[ARRAYSIZE(ThreadAccessValues)] = {};
  bool can_access_process = false;

  for (size_t i = 0; i < ARRAYSIZE(ProcessAccessValues); i++) {
    const void* Handle = OpenProcess(ProcessAccessValues[i], false, process_id);
    if (Handle != NULL) {
      allowed_process_access[i] = true;
      can_access_process = true;
      CloseHandle(Handle);
    }
  }

  if (!can_access_process) {
    fprintf(stdout, "No access to process.\n");
    return 0;
  }

  for (size_t i = 0; i < ARRAYSIZE(ThreadAccessValues); i++) {
    const void* thread_handle =
        OpenThread(ThreadAccessValues[i], false, thread_id);

    if (thread_handle != NULL) {
      allowed_thread_access[i] = true;
      CloseHandle(thread_handle);
    }
  }

  fprintf(stdout, "allowed_process_access\n");

  for (size_t i = 0; i < ARRAYSIZE(allowed_process_access); i++) {
    if (allowed_process_access[i]) {
      fprintf(stdout, "\t%s\n", ProcessAccessString[i]);
    }
  }

  fprintf(stdout, "allowed_thread_access\n");

  for (size_t i = 0; i < ARRAYSIZE(allowed_thread_access); i++) {
    if (allowed_thread_access[i]) {
      fprintf(stdout, "\t%s\n", ThreadAccessString[i]);
    }
  }

  return 0;
}
