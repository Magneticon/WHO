// who.cpp
// Native Windows NT file-handle finder.

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <winnt.h>

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)
#endif
#ifndef STATUS_INVALID_INFO_CLASS
#define STATUS_INVALID_INFO_CLASS ((LONG)0xC0000003L)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((LONG)0xC0000002L)
#endif
#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((LONG)0x80000005L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((LONG)0xC0000023L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif

#define SystemHandleInformation 16
#define SystemExtendedHandleInformation 64
#define ObjectNameInformation 1

typedef LONG (WINAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef LONG (WINAPI *PFN_NtQueryObject)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength);

typedef DWORD (WINAPI *PFN_GetModuleBaseNameW)(
    HANDLE hProcess,
    HMODULE hModule,
    LPWSTR lpBaseName,
    DWORD nSize);

typedef DWORD (WINAPI *PFN_GetModuleFileNameExW)(
    HANDLE hProcess,
    HMODULE hModule,
    LPWSTR lpFilename,
    DWORD nSize);

typedef BOOL (WINAPI *PFN_ProcessIdToSessionId)(
    DWORD dwProcessId,
    DWORD* pSessionId);

typedef BOOL (WINAPI *PFN_EnumProcesses)(
    DWORD* lpidProcess,
    DWORD cb,
    DWORD* lpcbNeeded);

typedef BOOL (WINAPI *PFN_IsWow64Process)(
    HANDLE hProcess,
    PBOOL Wow64Process);

typedef struct _WHO_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} WHO_UNICODE_STRING;

typedef struct _WHO_OBJECT_NAME_INFORMATION {
    WHO_UNICODE_STRING Name;
    WCHAR NameBuffer[1];
} WHO_OBJECT_NAME_INFORMATION;

// Classic SystemHandleInformation (class 16) entry layout for NT 3.51+,
// including NT 4, Windows 2000, XP and Server 2003.
//
// Do not pack this structure. Its native size is:
//   x86: 0x10 (16 bytes)
//   x64: 0x18 (24 bytes)
typedef struct _WHO_SYSTEM_HANDLE_ENTRY_LEGACY {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} WHO_SYSTEM_HANDLE_ENTRY_LEGACY;

typedef struct _WHO_SYSTEM_HANDLE_INFORMATION_LEGACY {
    ULONG NumberOfHandles;
    WHO_SYSTEM_HANDLE_ENTRY_LEGACY Handles[1];
} WHO_SYSTEM_HANDLE_INFORMATION_LEGACY;

#ifdef _WIN64
typedef char WHO_ASSERT_LEGACY_ENTRY_SIZE[(sizeof(WHO_SYSTEM_HANDLE_ENTRY_LEGACY) == 24) ? 1 : -1];
#else
typedef char WHO_ASSERT_LEGACY_ENTRY_SIZE[(sizeof(WHO_SYSTEM_HANDLE_ENTRY_LEGACY) == 16) ? 1 : -1];
#endif

// Extended layout. If class 64 is unavailable, the program falls back to class 16.
typedef struct _WHO_SYSTEM_HANDLE_ENTRY_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} WHO_SYSTEM_HANDLE_ENTRY_EX;

typedef struct _WHO_SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    WHO_SYSTEM_HANDLE_ENTRY_EX Handles[1];
} WHO_SYSTEM_HANDLE_INFORMATION_EX;

typedef struct _WHO_HANDLE {
    DWORD Pid;
    ULONG_PTR HandleValue;
    UCHAR ObjectTypeIndex;
} WHO_HANDLE;

typedef struct _WHO_MATCH {
    DWORD Pid;
    ULONG_PTR HandleValue;
    DWORD SessionId;
    WCHAR ProcessName[128];
    WCHAR ProcessPath[1024];
    WCHAR UserName[256];
    WCHAR TargetType[16];
    WCHAR LockHint[32];
    WCHAR Path[2048];
} WHO_MATCH;


typedef struct _WHO_PROCESS_CACHE {
    DWORD Pid;
    BOOL Openable;
    WCHAR ProcessName[128];
    WCHAR ProcessPath[1024];
    WCHAR UserName[256];
    DWORD SessionId;
} WHO_PROCESS_CACHE;

static WHO_PROCESS_CACHE* g_ProcessCache = 0;
static DWORD g_ProcessCacheCount = 0;
static DWORD g_ProcessCacheCap = 0;


static PFN_NtQuerySystemInformation g_NtQuerySystemInformation = 0;
static PFN_NtQueryObject g_NtQueryObject = 0;
static PFN_GetModuleBaseNameW g_GetModuleBaseNameW = 0;
static PFN_GetModuleFileNameExW g_GetModuleFileNameExW = 0;
static PFN_EnumProcesses g_EnumProcesses = 0;
static PFN_ProcessIdToSessionId g_ProcessIdToSessionId = 0;
static PFN_IsWow64Process g_IsWow64Process = 0;
static HANDLE g_Heap = 0;
static LONG g_LastHandleStatus = 0;
static ULONG g_LastHandleClass = 0;
static ULONG g_LastHandleBufferSize = 0;
static ULONG g_LastHandleReturnLength = 0;
static DWORD g_EnumHandleCount = 0;
static DWORD g_OpenProcessCount = 0;
static DWORD g_DuplicateCount = 0;
static DWORD g_DiskHandleCount = 0;
static DWORD g_NameCount = 0;
static DWORD g_FileInfoTimeoutCount = 0;
static DWORD g_NameTimeoutCount = 0;
static UCHAR g_FileTypeIndex = 0;
static ULONG g_RawHandleCount = 0;
static BY_HANDLE_FILE_INFORMATION g_TargetInfo;
static BOOL g_TargetInfoValid = FALSE;
static BOOL g_ShowImagePath = FALSE;
static BOOL g_ShowFullPath = FALSE;
static BOOL g_PauseOutput = FALSE;


typedef struct _WHO_FILEINFO_WORK {
    HANDLE Handle;
    BY_HANDLE_FILE_INFORMATION Info;
    DWORD FileType;
    BOOL Success;
} WHO_FILEINFO_WORK;

typedef struct _WHO_NAME_WORK {
    HANDLE Handle;
    WCHAR Path[2048];
    BOOL Success;
} WHO_NAME_WORK;
static BYTE g_HandleHeaderBytes[32];

// Large scratch buffers are static rather than stack locals.
// This intentionally avoids the compiler's __chkstk helper so the
// executable can remain CRT-free.
static WCHAR g_PathScratch[2048];
static WCHAR g_VerifyPath[2048];
static WCHAR g_NtNameScratch[2048];
static WCHAR g_DosMapScratch[4096];
static WCHAR g_LineScratch[4096];
static WCHAR g_SeparatorScratch[4096];
static WCHAR g_ChunkScratch[2048];
static WCHAR g_ExactPath[2048];
static WCHAR g_ResolveFullScratch[2048];
static WCHAR g_ResolvePatternScratch[MAX_PATH];
static WCHAR g_ProcessFilterScratch[MAX_PATH];
static WCHAR g_CurrentDirScratch[2048];
static WHO_MATCH g_TempMatch;

// ----- Tiny runtime helpers: keep the executable independent of the VC runtime. -----

static void* WhoMemSet(void* dst, int ch, size_t count)
{
    unsigned char* p = (unsigned char*)dst;
    while (count--) *p++ = (unsigned char)ch;
    return dst;
}

static void* WhoMemCopy(void* dst, const void* src, size_t count)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (count--) *d++ = *s++;
    return dst;
}

static SIZE_T WLen(const WCHAR* s)
{
    SIZE_T n = 0;
    if (!s) return 0;
    while (s[n]) ++n;
    return n;
}

static void WCopy(WCHAR* dst, SIZE_T cap, const WCHAR* src)
{
    SIZE_T i = 0;
    if (!dst || cap == 0) return;
    if (src) {
        while (src[i] && i + 1 < cap) {
            dst[i] = src[i];
            ++i;
        }
    }
    dst[i] = 0;
}

static void WCat(WCHAR* dst, SIZE_T cap, const WCHAR* src)
{
    SIZE_T n = WLen(dst);
    if (n >= cap) return;
    WCopy(dst + n, cap - n, src);
}

static BOOL WEqualI(const WCHAR* a, const WCHAR* b)
{
    int la = (int)WLen(a);
    int lb = (int)WLen(b);
    if (la != lb) return FALSE;
    if (la == 0) return TRUE;
    return CompareStringW(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE,
                          a, la, b, lb) == CSTR_EQUAL;
}

static BOOL WStartsI(const WCHAR* text, const WCHAR* prefix)
{
    int lp = (int)WLen(prefix);
    int lt = (int)WLen(text);
    if (lp > lt) return FALSE;
    if (lp == 0) return TRUE;
    return CompareStringW(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE,
                          text, lp, prefix, lp) == CSTR_EQUAL;
}



static void UIntToDec(DWORD value, WCHAR* out, SIZE_T cap)
{
    WCHAR tmp[16];
    SIZE_T n = 0, i;
    if (cap == 0) return;
    if (value == 0) {
        WCopy(out, cap, L"0");
        return;
    }
    while (value && n < 15) {
        tmp[n++] = (WCHAR)(L'0' + (value % 10));
        value /= 10;
    }
    i = 0;
    while (n && i + 1 < cap) out[i++] = tmp[--n];
    out[i] = 0;
}

static void UIntPtrToHex(ULONG_PTR value, WCHAR* out, SIZE_T cap)
{
    static const WCHAR hex[] = L"0123456789ABCDEF";
    WCHAR tmp[2 * sizeof(ULONG_PTR) + 1];
    SIZE_T n = 0, i = 0;
    if (cap == 0) return;
    WCopy(out, cap, L"0x");
    if (cap <= 2) return;
    if (value == 0) {
        WCat(out, cap, L"0");
        return;
    }
    while (value && n < 2 * sizeof(ULONG_PTR)) {
        tmp[n++] = hex[(unsigned int)(value & 0xF)];
        value >>= 4;
    }
    i = WLen(out);
    while (n && i + 1 < cap) out[i++] = tmp[--n];
    out[i] = 0;
}

static void Out(const WCHAR* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0, written = 0;
    if (!s || h == INVALID_HANDLE_VALUE) return;

    if (GetConsoleMode(h, &mode)) {
        WriteConsoleW(h, s, (DWORD)WLen(s), &written, 0);
    } else {
        int need = WideCharToMultiByte(CP_ACP, 0, s, -1, 0, 0, 0, 0);
        if (need > 1) {
            char* b = (char*)HeapAlloc(g_Heap, 0, need);
            if (b) {
                int got = WideCharToMultiByte(CP_ACP, 0, s, -1, b, need, 0, 0);
                if (got > 1) WriteFile(h, b, (DWORD)(got - 1), &written, 0);
                HeapFree(g_Heap, 0, b);
            }
        }
    }
}

static void Err(const WCHAR* s)
{
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    DWORD mode = 0, written = 0;
    if (!s || h == INVALID_HANDLE_VALUE) return;

    if (GetConsoleMode(h, &mode)) {
        WriteConsoleW(h, s, (DWORD)WLen(s), &written, 0);
    } else {
        int need = WideCharToMultiByte(CP_ACP, 0, s, -1, 0, 0, 0, 0);
        if (need > 1) {
            char* b = (char*)HeapAlloc(g_Heap, 0, need);
            if (b) {
                int got = WideCharToMultiByte(CP_ACP, 0, s, -1, b, need, 0, 0);
                if (got > 1) WriteFile(h, b, (DWORD)(got - 1), &written, 0);
                HeapFree(g_Heap, 0, b);
            }
        }
    }
}

static void OutLn(const WCHAR* s)
{
    Out(s);
    Out(L"\r\n");
}

static void AppendField(WCHAR* line, SIZE_T cap, const WCHAR* value, SIZE_T width)
{
    SIZE_T i, n = WLen(value);
    WCat(line, cap, value);
    if (n < width) {
        for (i = n; i < width; ++i) WCat(line, cap, L" ");
    }
}

static BOOL LoadApis()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE psapi = LoadLibraryW(L"psapi.dll");
    if (!ntdll) return FALSE;

    g_NtQuerySystemInformation =
        (PFN_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    g_NtQueryObject =
        (PFN_NtQueryObject)GetProcAddress(ntdll, "NtQueryObject");

    if (psapi) {
        g_GetModuleBaseNameW =
            (PFN_GetModuleBaseNameW)GetProcAddress(psapi, "GetModuleBaseNameW");
        g_GetModuleFileNameExW =
            (PFN_GetModuleFileNameExW)GetProcAddress(psapi, "GetModuleFileNameExW");
        g_EnumProcesses =
            (PFN_EnumProcesses)GetProcAddress(psapi, "EnumProcesses");
    }

    if (kernel32) {
        g_IsWow64Process =
            (PFN_IsWow64Process)GetProcAddress(kernel32, "IsWow64Process");
        g_ProcessIdToSessionId =
            (PFN_ProcessIdToSessionId)GetProcAddress(kernel32, "ProcessIdToSessionId");
    }

    return g_NtQuerySystemInformation && g_NtQueryObject;
}

#ifndef _WIN64
static BOOL RunningUnderWow64()
{
    BOOL wow = FALSE;
    if (g_IsWow64Process &&
        g_IsWow64Process(GetCurrentProcess(), &wow) &&
        wow)
        return TRUE;
    return FALSE;
}
#endif

// ----- Command line parser. Paths containing spaces may be quoted. -----

static WCHAR LowerAsciiW(WCHAR c);

static void TrimToken(WCHAR* s)
{
    SIZE_T n;
    WCHAR* p;

    if (!s) return;

    p = s;
    while (*p == L' ' || *p == L'\t') ++p;
    if (p != s) {
        WCHAR* d = s;
        while (*p) *d++ = *p++;
        *d = 0;
    }

    n = WLen(s);
    while (n && (s[n - 1] == L' ' || s[n - 1] == L'\t')) {
        s[n - 1] = 0;
        --n;
    }
}

static void RemoveOuterQuotes(WCHAR* s)
{
    SIZE_T n;
    if (!s) return;
    TrimToken(s);
    n = WLen(s);
    if (n >= 2 &&
        ((s[0] == L'"' && s[n - 1] == L'"') ||
         (s[0] == L'\'' && s[n - 1] == L'\''))) {
        SIZE_T i;
        for (i = 1; i + 1 < n; ++i)
            s[i - 1] = s[i];
        s[n - 2] = 0;
    }
}

static BOOL OptionTakesValue(WCHAR ch)
{
    ch = LowerAsciiW(ch);
    return ch == L'i' || ch == L'p' || ch == L'h';
}

static int ParseCommandLine(WCHAR*** outArgv, WCHAR** outStorage)
{
    WCHAR* raw = GetCommandLineW();
    SIZE_T len = WLen(raw);
    WCHAR* storage;
    WCHAR** argv;
    WCHAR* src;
    WCHAR* dst;
    int argc = 0;
    BOOL haveTarget = FALSE;

    storage = (WCHAR*)HeapAlloc(
        g_Heap, HEAP_ZERO_MEMORY, (len + 16) * sizeof(WCHAR));
    argv = (WCHAR**)HeapAlloc(
        g_Heap, HEAP_ZERO_MEMORY, 64 * sizeof(WCHAR*));

    if (!storage || !argv) {
        if (storage) HeapFree(g_Heap, 0, storage);
        if (argv) HeapFree(g_Heap, 0, argv);
        return 0;
    }

    src = raw;
    dst = storage;

    /*
      Keep argv[0]. WhoMain intentionally follows the conventional argv layout
      and starts parsing at argv[1].
    */
    argv[argc++] = dst;
    WCopy(dst, 4, L"who");
    dst += 4;

    /* Skip the real executable name in GetCommandLineW(). */
    while (*src == L' ' || *src == L'\t') ++src;
    if (*src == L'"' || *src == L'\'') {
        WCHAR q = *src++;
        while (*src && *src != q) ++src;
        if (*src == q) ++src;
    } else {
        while (*src && *src != L' ' && *src != L'\t') ++src;
    }
    while (*src == L' ' || *src == L'\t') ++src;

    while (*src && argc < 62) {
        if (*src == L'/') {
            WCHAR opt;
            WCHAR* valueStart;

            ++src;
            while (*src == L' ' || *src == L'\t') ++src;
            if (!*src) break;

            opt = LowerAsciiW(*src++);

            argv[argc++] = dst;
            *dst++ = L'/';
            *dst++ = opt;
            *dst++ = 0;

            /*
              /i, /p and /h take values. The value extends to the next slash,
              so spaces do not require quotes:

                  /iGoogle Chrome/c
                  /i Google Chrome /c
                  /p6096
                  /p 6096
            */
            if (OptionTakesValue(opt)) {
                while (*src == L' ' || *src == L'\t') ++src;

                valueStart = dst;
                while (*src && *src != L'/')
                    *dst++ = *src++;
                *dst++ = 0;

                TrimToken(valueStart);
                RemoveOuterQuotes(valueStart);

                if (*valueStart)
                    argv[argc++] = valueStart;

                continue;
            }

            /*
              Flag options take no value. If text follows a flag before the
              next slash and no target has been supplied yet, treat that text
              as the target. This keeps both forms valid:

                  who /a d*
                  who d* followed by /a
            */
            while (*src == L' ' || *src == L'\t') ++src;
            if (*src && *src != L'/' && !haveTarget) {
                valueStart = dst;
                while (*src && *src != L'/')
                    *dst++ = *src++;
                *dst++ = 0;

                TrimToken(valueStart);
                RemoveOuterQuotes(valueStart);

                if (*valueStart) {
                    argv[argc++] = valueStart;
                    haveTarget = TRUE;
                }
            }

            continue;
        }

        /*
          Text outside slash-options is the target. It extends to the next
          slash and may contain spaces without quotes:

              who \something\my file/c
        */
        {
            WCHAR* target = dst;
            while (*src && *src != L'/')
                *dst++ = *src++;
            *dst++ = 0;

            TrimToken(target);
            RemoveOuterQuotes(target);

            if (*target) {
                argv[argc++] = target;
                haveTarget = TRUE;
            }
        }
    }

    *outArgv = argv;
    *outStorage = storage;
    return argc;
}



// ----- Path handling -----

static void TrimTrailingSlash(WCHAR* p)
{
    SIZE_T n = WLen(p);
    while (n > 3 && (p[n - 1] == L'\\' || p[n - 1] == L'/')) {
        p[n - 1] = 0;
        --n;
    }
}

static BOOL ResolveExistingLocalPath(const WCHAR* arg, WCHAR* full, SIZE_T cap);


static BOOL ContainsPathSeparator(const WCHAR* s)
{
    SIZE_T i;
    if (!s) return FALSE;
    for (i = 0; s[i]; ++i) {
        if (s[i] == L'\\' || s[i] == L'/')
            return TRUE;
    }
    return FALSE;
}

static BOOL HasExtensionInLastComponent(const WCHAR* s)
{
    const WCHAR* p;
    const WCHAR* lastSep = 0;
    const WCHAR* lastDot = 0;

    if (!s) return FALSE;

    for (p = s; *p; ++p) {
        if (*p == L'\\' || *p == L'/')
            lastSep = p;
        else if (*p == L'.')
            lastDot = p;
    }

    return lastDot != 0 && (lastSep == 0 || lastDot > lastSep);
}

/*
  Resolve a target for destructive close mode.

  First try the argument literally. If it does not exist and the argument
  names only a simple current-directory item without an extension, search
  "<name>.*" in the current directory.

  Success requires exactly ONE matching filesystem object. This makes:

      who d c

  resolve to d.txt only when d.txt is the unique "d.*" object in CWD.
*/

static BOOL AddUniqueMatch(WHO_MATCH** array, DWORD* count, DWORD* capacity,
                           const WHO_MATCH* m)
{
    DWORD i;
    WHO_MATCH* next;
    DWORD newCap;

    for (i = 0; i < *count; ++i) {
        if ((*array)[i].Pid == m->Pid &&
            (*array)[i].HandleValue == m->HandleValue)
            return TRUE;
    }

    if (*count >= *capacity) {
        newCap = (*capacity == 0) ? 64 : (*capacity * 2);
        if (*array)
            next = (WHO_MATCH*)HeapReAlloc(g_Heap, 0, *array, newCap * sizeof(WHO_MATCH));
        else
            next = (WHO_MATCH*)HeapAlloc(g_Heap, 0, newCap * sizeof(WHO_MATCH));
        if (!next) return FALSE;
        *array = next;
        *capacity = newCap;
    }

    WhoMemCopy(&(*array)[*count], m, sizeof(WHO_MATCH));
    ++(*count);
    return TRUE;
}

static BOOL AddUniquePath(WCHAR*** array, DWORD* count, DWORD* capacity,
                          const WCHAR* path)
{
    DWORD i;
    WCHAR** next;
    WCHAR* copy;
    SIZE_T chars;

    for (i = 0; i < *count; ++i) {
        if (WEqualI((*array)[i], path))
            return TRUE;
    }

    if (*count >= *capacity) {
        DWORD newCap = (*capacity == 0) ? 8 : (*capacity * 2);
        if (*array)
            next = (WCHAR**)HeapReAlloc(g_Heap, HEAP_ZERO_MEMORY,
                                       *array, newCap * sizeof(WCHAR*));
        else
            next = (WCHAR**)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY,
                                     newCap * sizeof(WCHAR*));
        if (!next) return FALSE;
        *array = next;
        *capacity = newCap;
    }

    chars = WLen(path) + 1;
    copy = (WCHAR*)HeapAlloc(g_Heap, 0, chars * sizeof(WCHAR));
    if (!copy) return FALSE;
    WCopy(copy, chars, path);

    (*array)[*count] = copy;
    ++(*count);
    return TRUE;
}

static void FreePathArray(WCHAR** paths, DWORD count)
{
    DWORD i;
    if (!paths) return;
    for (i = 0; i < count; ++i)
        if (paths[i]) HeapFree(g_Heap, 0, paths[i]);
    HeapFree(g_Heap, 0, paths);
}

static BOOL HasWildcard(const WCHAR* s);

static BOOL ResolveCloseTargets(const WCHAR* arg,
                                WCHAR*** outPaths,
                                DWORD* outCount)
{
    WIN32_FIND_DATAW fd;
    HANDLE find;
    WCHAR** paths = 0;
    DWORD count = 0, cap = 0;

    *outPaths = 0;
    *outCount = 0;

    if (ResolveExistingLocalPath(arg, g_ResolveFullScratch,
                                 sizeof(g_ResolveFullScratch) / sizeof(g_ResolveFullScratch[0]))) {
        if (!AddUniquePath(&paths, &count, &cap, g_ResolveFullScratch))
            return FALSE;
        *outPaths = paths;
        *outCount = count;
        return TRUE;
    }

    // Wildcards are intentionally limited to the current directory here.
    // Destructive close mode should never silently expand across arbitrary
    // directory trees.
    if (ContainsPathSeparator(arg))
        return FALSE;

    if (HasWildcard(arg)) {
        WCopy(g_ResolvePatternScratch, sizeof(g_ResolvePatternScratch) / sizeof(g_ResolvePatternScratch[0]), arg);
    } else if (!HasExtensionInLastComponent(arg)) {
        WCopy(g_ResolvePatternScratch, sizeof(g_ResolvePatternScratch) / sizeof(g_ResolvePatternScratch[0]), arg);
        WCat(g_ResolvePatternScratch, sizeof(g_ResolvePatternScratch) / sizeof(g_ResolvePatternScratch[0]), L".*");
    } else {
        return FALSE;
    }

    find = FindFirstFileW(g_ResolvePatternScratch, &fd);
    if (find == INVALID_HANDLE_VALUE)
        return FALSE;

    do {
        if (WEqualI(fd.cFileName, L".") ||
            WEqualI(fd.cFileName, L".."))
            continue;

        if (!ResolveExistingLocalPath(fd.cFileName, g_ResolveFullScratch,
                                      sizeof(g_ResolveFullScratch) / sizeof(g_ResolveFullScratch[0])))
            continue;

        if (!AddUniquePath(&paths, &count, &cap, g_ResolveFullScratch)) {
            FindClose(find);
            FreePathArray(paths, count);
            return FALSE;
        }
    } while (FindNextFileW(find, &fd));

    FindClose(find);

    if (!count) {
        FreePathArray(paths, count);
        return FALSE;
    }

    *outPaths = paths;
    *outCount = count;
    return TRUE;
}

static const WCHAR* BaseNamePtr(const WCHAR* path)
{
    const WCHAR* p;
    const WCHAR* base = path;
    if (!path) return L"";
    for (p = path; *p; ++p)
        if (*p == L'\\' || *p == L'/')
            base = p + 1;
    return base;
}

static BOOL PathIsInDirectoryI(const WCHAR* fullPath, const WCHAR* directory)
{
    SIZE_T dirLen;
    const WCHAR* base;

    if (!fullPath || !directory)
        return FALSE;

    dirLen = WLen(directory);
    if (!dirLen)
        return FALSE;

    if (!WStartsI(fullPath, directory))
        return FALSE;

    if (fullPath[dirLen] != L'\\' && fullPath[dirLen] != L'/')
        return FALSE;

    base = fullPath + dirLen + 1;

    // Only direct children of the current directory, not descendants.
    while (*base) {
        if (*base == L'\\' || *base == L'/')
            return FALSE;
        ++base;
    }

    return TRUE;
}

static BOOL IsBroadPattern(const WCHAR* query)
{
    if (!query || !*query)
        return FALSE;
    return HasWildcard(query);
}


static BOOL WildMatchI(const WCHAR* pattern, const WCHAR* text);

static BOOL NameCriterionMatches(const WCHAR* criterion, const WCHAR* fullPath)
{
    const WCHAR* base;
    WCHAR stem[512];
    SIZE_T n;

    if (!criterion || !*criterion || !fullPath || !*fullPath)
        return FALSE;

    // If the user supplied a path component, apply wildcard matching to the
    // full resolved path.
    if (ContainsPathSeparator(criterion))
        return WildMatchI(criterion, fullPath);

    base = BaseNamePtr(fullPath);

    // Explicit wildcard: match against the complete basename.
    if (HasWildcard(criterion))
        return WildMatchI(criterion, base);

    // Explicit extension: exact basename match.
    if (HasExtensionInLastComponent(criterion))
        return WEqualI(criterion, base);

    // No extension: match the basename stem. Therefore "d" matches d.txt,
    // d.ini, or an extensionless filesystem object named d.
    WCopy(stem, sizeof(stem) / sizeof(stem[0]), base);
    n = WLen(stem);
    while (n) {
        --n;
        if (stem[n] == L'.') {
            stem[n] = 0;
            break;
        }
        if (stem[n] == L'\\' || stem[n] == L'/')
            break;
    }

    return WEqualI(criterion, stem) || WEqualI(criterion, base);
}


static BOOL ResolveExistingLocalPath(const WCHAR* arg, WCHAR* full, SIZE_T cap)
{
    DWORD attrs;
    DWORD got = GetFullPathNameW(arg, (DWORD)cap, full, 0);
    if (!got || got >= cap) return FALSE;
    attrs = GetFileAttributesW(full);
    if (attrs == INVALID_FILE_ATTRIBUTES) return FALSE;
    TrimTrailingSlash(full);
    return TRUE;
}

static BOOL NtPathToDosPath(const WCHAR* ntPath, WCHAR* out, SIZE_T cap)
{
    WCHAR drive[3] = L"A:";
    WCHAR* one;
    WCHAR letter;

    if (!ntPath || !out || cap == 0) return FALSE;

    if (WStartsI(ntPath, L"\\??\\")) {
        WCopy(out, cap, ntPath + 4);
        return TRUE;
    }

    for (letter = L'A'; letter <= L'Z'; ++letter) {
        drive[0] = letter;
        g_DosMapScratch[0] = 0;

        if (!QueryDosDeviceW(drive, g_DosMapScratch, (DWORD)(sizeof(g_DosMapScratch) / sizeof(g_DosMapScratch[0]))))
            continue;

        one = g_DosMapScratch;
        while (*one) {
            SIZE_T n = WLen(one);
            if (WStartsI(ntPath, one)) {
                WCopy(out, cap, drive);
                WCat(out, cap, ntPath + n);
                return TRUE;
            }
            one += n + 1;
        }
    }

    WCopy(out, cap, ntPath);
    return FALSE;
}

static BOOL QueryHandleNtName(HANDLE h, WCHAR* out, SIZE_T cap)
{
    ULONG need = 0;
    ULONG size = 1024;
    PVOID buffer = 0;
    LONG st;

    if (!g_NtQueryObject) return FALSE;

    for (;;) {
        buffer = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, size);
        if (!buffer) return FALSE;

        st = g_NtQueryObject(h, ObjectNameInformation, buffer, size, &need);
        if (st == STATUS_INFO_LENGTH_MISMATCH || (need > size && !NT_SUCCESS(st))) {
            HeapFree(g_Heap, 0, buffer);
            buffer = 0;
            size = need ? need + 512 : size * 2;
            if (size > 1024 * 1024) return FALSE;
            continue;
        }

        if (!NT_SUCCESS(st)) {
            HeapFree(g_Heap, 0, buffer);
            return FALSE;
        }

        {
            WHO_OBJECT_NAME_INFORMATION* oni = (WHO_OBJECT_NAME_INFORMATION*)buffer;
            SIZE_T chars;
            if (!oni->Name.Buffer || oni->Name.Length == 0) {
                HeapFree(g_Heap, 0, buffer);
                return FALSE;
            }

            chars = oni->Name.Length / sizeof(WCHAR);
            if (chars + 1 > cap) chars = cap - 1;
            WhoMemCopy(out, oni->Name.Buffer, chars * sizeof(WCHAR));
            out[chars] = 0;
        }

        HeapFree(g_Heap, 0, buffer);
        return TRUE;
    }
}

static BOOL QueryHandleDosPath(HANDLE h, WCHAR* out, SIZE_T cap)
{
    DWORD type = GetFileType(h);
    if (type != FILE_TYPE_DISK) return FALSE;
    if (!QueryHandleNtName(h, g_NtNameScratch, sizeof(g_NtNameScratch) / sizeof(g_NtNameScratch[0])))
        return FALSE;
    NtPathToDosPath(g_NtNameScratch, out, cap);
    TrimTrailingSlash(out);
    return TRUE;
}

static DWORD WINAPI FileInfoWorker(LPVOID param)
{
    WHO_FILEINFO_WORK* w = (WHO_FILEINFO_WORK*)param;

    w->FileType = GetFileType(w->Handle);
    if (w->FileType != FILE_TYPE_DISK) {
        w->Success = FALSE;
        return 0;
    }

    w->Success = GetFileInformationByHandle(w->Handle, &w->Info);
    return 0;
}

// 0 = no match/query failed
// 1 = same file
// 2 = timed out; caller must leave duplicated handle open
static int SameFileIdentityTimed(HANDLE h,
                                 const BY_HANDLE_FILE_INFORMATION* target,
                                 DWORD timeoutMs)
{
    WHO_FILEINFO_WORK* w;
    HANDLE thread;
    DWORD wait;
    int result = 0;

    if (!target) return 0;

    w = (WHO_FILEINFO_WORK*)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, sizeof(*w));
    if (!w) return 0;
    w->Handle = h;

    thread = CreateThread(0, 0, FileInfoWorker, w, 0, 0);
    if (!thread) {
        HeapFree(g_Heap, 0, w);
        return 0;
    }

    wait = WaitForSingleObject(thread, timeoutMs);

    if (wait == WAIT_OBJECT_0) {
        if (w->FileType == FILE_TYPE_DISK)
            ++g_DiskHandleCount;

        if (w->Success &&
            w->Info.dwVolumeSerialNumber == target->dwVolumeSerialNumber &&
            w->Info.nFileIndexHigh == target->nFileIndexHigh &&
            w->Info.nFileIndexLow == target->nFileIndexLow) {
            result = 1;
        }

        CloseHandle(thread);
        HeapFree(g_Heap, 0, w);
        return result;
    }

    if (wait == WAIT_TIMEOUT) {
        ++g_FileInfoTimeoutCount;

        // Do not wait for a thread that may be stuck in kernel mode.
        // Request termination, close our thread handle, and deliberately leave
        // the tiny context plus duplicated file handle alive until who.exe exits.
        TerminateThread(thread, 1);
        CloseHandle(thread);
        return 2;
    }

    CloseHandle(thread);
    HeapFree(g_Heap, 0, w);
    return 0;
}

static DWORD WINAPI NameQueryWorker(LPVOID param)
{
    WHO_NAME_WORK* w = (WHO_NAME_WORK*)param;
    w->Success = QueryHandleDosPath(
        w->Handle, w->Path, sizeof(w->Path) / sizeof(w->Path[0]));
    return 0;
}

// Return values:
//   0 = query failed / no usable name
//   1 = path returned
//   2 = timed out; caller must leave duplicated handle open
static int QueryHandleDosPathTimed(HANDLE h, WCHAR* out, SIZE_T cap,
                                   DWORD timeoutMs)
{
    WHO_NAME_WORK* w;
    HANDLE thread;
    DWORD wait;

    w = (WHO_NAME_WORK*)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, sizeof(*w));
    if (!w) return 0;
    w->Handle = h;

    thread = CreateThread(0, 0, NameQueryWorker, w, 0, 0);
    if (!thread) {
        HeapFree(g_Heap, 0, w);
        return 0;
    }

    wait = WaitForSingleObject(thread, timeoutMs);

    if (wait == WAIT_OBJECT_0) {
        int result = 0;
        if (w->Success) {
            WCopy(out, cap, w->Path);
            result = 1;
        }
        CloseHandle(thread);
        HeapFree(g_Heap, 0, w);
        return result;
    }

    if (wait == WAIT_TIMEOUT) {
        ++g_NameTimeoutCount;
        // On old NT a thread blocked in a filesystem/native query may remain
        // stuck in kernel mode. Request termination, but do not wait for it.
        // The tiny worker context and duplicated handle are intentionally
        // reclaimed by process teardown.
        TerminateThread(thread, 1);
        CloseHandle(thread);
        return 2;
    }

    CloseHandle(thread);
    HeapFree(g_Heap, 0, w);
    return 0;
}



static void QueryTargetType(const WCHAR* path, WCHAR* out, SIZE_T cap)
{
    DWORD attrs;

    WCopy(out, cap, L"file");
    if (!path || !*path) {
        WCopy(out, cap, L"?");
        return;
    }

    attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        WCopy(out, cap, L"?");
        return;
    }

    if (attrs & FILE_ATTRIBUTE_DIRECTORY)
        WCopy(out, cap, L"dir");
    else
        WCopy(out, cap, L"file");
}

static void QueryLockHint(const WCHAR* path, WCHAR* out, SIZE_T cap)
{
    HANDLE h;
    DWORD err;

    WCopy(out, cap, L"open");
    if (!path || !*path)
        return;

    h = CreateFileW(path,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    0,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    0);

    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        WCopy(out, cap, L"open");
        return;
    }

    err = GetLastError();
    if (err == ERROR_SHARING_VIOLATION)
        WCopy(out, cap, L"blocking");
    else if (err == ERROR_ACCESS_DENIED)
        WCopy(out, cap, L"unknown");
    else
        WCopy(out, cap, L"unknown");
}


// ----- Process metadata -----


static void QueryProcessPath(HANDLE process, WCHAR* out, SIZE_T cap)
{
    WCopy(out, cap, L"<unknown>");
    if (g_GetModuleFileNameExW) {
        DWORD got = g_GetModuleFileNameExW(process, 0, out, (DWORD)cap);
        if (got && got < cap)
            return;
    }
}

static DWORD QueryProcessSessionId(DWORD pid)
{
    DWORD sid = 0xFFFFFFFFUL;
    if (g_ProcessIdToSessionId &&
        g_ProcessIdToSessionId(pid, &sid))
        return sid;
    return 0xFFFFFFFFUL;
}

static void QueryProcessName(HANDLE process, WCHAR* out, SIZE_T cap)
{
    WCopy(out, cap, L"<unknown>");
    if (g_GetModuleBaseNameW) {
        DWORD got = g_GetModuleBaseNameW(process, 0, out, (DWORD)cap);
        if (got && got < cap) return;
    }
}

static void QueryProcessUser(HANDLE process, WCHAR* out, SIZE_T cap)
{
    HANDLE token = 0;
    DWORD need = 0;
    BYTE* buffer = 0;
    TOKEN_USER* tu;
    WCHAR name[128];
    WCHAR domain[128];
    DWORD nameLen = sizeof(name) / sizeof(name[0]);
    DWORD domainLen = sizeof(domain) / sizeof(domain[0]);
    SID_NAME_USE use;

    WCopy(out, cap, L"<unknown>");

    if (!OpenProcessToken(process, TOKEN_QUERY, &token))
        return;

    GetTokenInformation(token, TokenUser, 0, 0, &need);
    if (!need) {
        CloseHandle(token);
        return;
    }

    buffer = (BYTE*)HeapAlloc(g_Heap, 0, need);
    if (!buffer) {
        CloseHandle(token);
        return;
    }

    if (!GetTokenInformation(token, TokenUser, buffer, need, &need)) {
        HeapFree(g_Heap, 0, buffer);
        CloseHandle(token);
        return;
    }

    tu = (TOKEN_USER*)buffer;
    name[0] = domain[0] = 0;

    if (LookupAccountSidW(0, tu->User.Sid, name, &nameLen,
                          domain, &domainLen, &use)) {
        if (domain[0]) {
            WCopy(out, cap, domain);
            WCat(out, cap, L"\\");
            WCat(out, cap, name);
        } else {
            WCopy(out, cap, name);
        }
    }

    HeapFree(g_Heap, 0, buffer);
    CloseHandle(token);
}

// ----- Handle enumeration -----

static BOOL AddHandle(WHO_HANDLE** array, DWORD* count, DWORD* capacity,
                      DWORD pid, ULONG_PTR handleValue, UCHAR objectTypeIndex)
{
    WHO_HANDLE* next;
    DWORD newCap;

    if (*count >= *capacity) {
        newCap = (*capacity == 0) ? 4096 : (*capacity * 2);
        if (*array)
            next = (WHO_HANDLE*)HeapReAlloc(g_Heap, 0, *array, newCap * sizeof(WHO_HANDLE));
        else
            next = (WHO_HANDLE*)HeapAlloc(g_Heap, 0, newCap * sizeof(WHO_HANDLE));

        if (!next) return FALSE;
        *array = next;
        *capacity = newCap;
    }

    (*array)[*count].Pid = pid;
    (*array)[*count].HandleValue = handleValue;
    (*array)[*count].ObjectTypeIndex = objectTypeIndex;
    ++(*count);
    return TRUE;
}

static BOOL EnumerateSystemHandles(WHO_HANDLE** outHandles, DWORD* outCount)
{
    ULONG size = 1024 * 1024;
    BYTE* buffer = 0;
    ULONG need = 0;
    LONG st = STATUS_INVALID_INFO_CLASS;
#ifdef _WIN64
    BOOL useExtended = TRUE;
#else
    // On XP x64 under WOW64, class 64 may return a native-width extended
    // table that a 32-bit process must not parse with 32-bit pointer fields.
    // The classic class 16 table is the correct/compatible choice for x86.
    BOOL useExtended = FALSE;
#endif
    WHO_HANDLE* result = 0;
    DWORD count = 0, capacity = 0;
    *outHandles = 0;
    *outCount = 0;

    // x86 builds deliberately use classic SystemHandleInformation (16).
    // Native x64 builds try SystemExtendedHandleInformation (64) first and
    // fall back to class 16 if needed.
    for (;;) {
        buffer = (BYTE*)HeapAlloc(g_Heap, 0, size);
        if (!buffer) return FALSE;

        need = 0;
        st = g_NtQuerySystemInformation(
            useExtended ? SystemExtendedHandleInformation : SystemHandleInformation,
            buffer, size, &need);

        g_LastHandleStatus = st;
        g_LastHandleClass = useExtended ? SystemExtendedHandleInformation : SystemHandleInformation;
        g_LastHandleBufferSize = size;
        g_LastHandleReturnLength = need;

        if (st == STATUS_INFO_LENGTH_MISMATCH ||
            st == STATUS_BUFFER_TOO_SMALL ||
            st == STATUS_BUFFER_OVERFLOW) {
            HeapFree(g_Heap, 0, buffer);
            buffer = 0;
            if (need > size)
                size = need + 65536;
            else
                size *= 2;
            if (size > 256 * 1024 * 1024)
                return FALSE;
            continue;
        }

        if (!NT_SUCCESS(st) && useExtended) {
            // Class 64 is not present on some XP/older NT versions, and some
            // builds return a status other than STATUS_INVALID_INFO_CLASS.
            // Retry from scratch with the classic class 16 table.
            HeapFree(g_Heap, 0, buffer);
            buffer = 0;
            useExtended = FALSE;
            size = 1024 * 1024;
            continue;
        }

        if (!NT_SUCCESS(st)) {
            HeapFree(g_Heap, 0, buffer);
            return FALSE;
        }

        break;
    }

    WhoMemSet(g_HandleHeaderBytes, 0, sizeof(g_HandleHeaderBytes));
    WhoMemCopy(g_HandleHeaderBytes, buffer,
           size < sizeof(g_HandleHeaderBytes) ? size : sizeof(g_HandleHeaderBytes));

    if (useExtended) {
        // Extended class 64: header is 2 pointer-sized fields, entry is
        // 7 pointer/word fields with native alignment. We only need PID,
        // handle value and ObjectTypeIndex.
#ifdef _WIN64
        BYTE* base = buffer + 16;
        ULONG_PTR n = *(ULONG_PTR*)buffer;
        ULONG_PTR j;
        g_RawHandleCount = (ULONG)n;
        for (j = 0; j < n; ++j) {
            BYTE* e = base + j * 40; // SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX x64
            ULONG_PTR pidp = *(ULONG_PTR*)(e + 8);
            ULONG_PTR hv = *(ULONG_PTR*)(e + 16);
            USHORT type = *(USHORT*)(e + 30);
            if (!pidp || pidp > 0xFFFFFFFFUL) continue;
            if (!AddHandle(&result, &count, &capacity,
                           (DWORD)pidp, hv, (UCHAR)type)) {
                HeapFree(g_Heap, 0, buffer);
                if (result) HeapFree(g_Heap, 0, result);
                return FALSE;
            }
        }
#else
        // Currently not used by the Win32 build, but retained for completeness.
        BYTE* base = buffer + 8;
        ULONG_PTR n = *(ULONG_PTR*)buffer;
        ULONG_PTR j;
        g_RawHandleCount = (ULONG)n;
        for (j = 0; j < n; ++j) {
            BYTE* e = base + j * 28;
            ULONG_PTR pidp = *(ULONG_PTR*)(e + 4);
            ULONG_PTR hv = *(ULONG_PTR*)(e + 8);
            USHORT type = *(USHORT*)(e + 18);
            if (!pidp) continue;
            if (!AddHandle(&result, &count, &capacity,
                           (DWORD)pidp, hv, (UCHAR)type)) {
                HeapFree(g_Heap, 0, buffer);
                if (result) HeapFree(g_Heap, 0, result);
                return FALSE;
            }
        }
#endif
    } else {
        // Classic class 16. Parse the returned bytes explicitly rather than
        // relying on a C structure embedded after the count. This matters on
        // old NT/WOW64 combinations where header alignment is easy to get wrong.
        ULONG n = *(ULONG*)buffer;
        ULONG j;
        ULONG header = 4;
        ULONG stride = 16;

#ifdef _WIN64
        header = 8;
        stride = 24;
#else
        // A 32-bit caller normally receives the 16-byte x86 form.
        // If ReturnLength unmistakably describes the native x64 form, accept
        // that too; the fields we need are at the same first 8-byte offsets.
        if (need != 0 && n != 0) {
            ULONGLONG want32 = 4ULL + ((ULONGLONG)n * 16ULL);
            ULONGLONG want64 = 8ULL + ((ULONGLONG)n * 24ULL);
            ULONGLONG d32 = (need > want32) ? (need - want32) : (want32 - need);
            ULONGLONG d64 = (need > want64) ? (need - want64) : (want64 - need);
            if (d64 < d32) {
                header = 8;
                stride = 24;
            }
        }
#endif

        g_RawHandleCount = n;
        for (j = 0; j < n; ++j) {
            BYTE* e = buffer + header + ((ULONG_PTR)j * stride);
            USHORT pid16 = *(USHORT*)(e + 0);
            UCHAR type = *(UCHAR*)(e + 4);
            USHORT hv16 = *(USHORT*)(e + 6);

            if (!pid16) continue;
            if (!AddHandle(&result, &count, &capacity,
                           (DWORD)pid16, (ULONG_PTR)hv16, type)) {
                HeapFree(g_Heap, 0, buffer);
                if (result) HeapFree(g_Heap, 0, result);
                return FALSE;
            }
        }
    }

    HeapFree(g_Heap, 0, buffer);
    *outHandles = result;
    *outCount = count;
    return TRUE;
}

static BOOL AddMatch(WHO_MATCH** array, DWORD* count, DWORD* capacity,
                     const WHO_MATCH* m)
{
    WHO_MATCH* next;
    DWORD newCap;

    if (*count >= *capacity) {
        newCap = (*capacity == 0) ? 64 : (*capacity * 2);
        if (*array)
            next = (WHO_MATCH*)HeapReAlloc(g_Heap, 0, *array, newCap * sizeof(WHO_MATCH));
        else
            next = (WHO_MATCH*)HeapAlloc(g_Heap, 0, newCap * sizeof(WHO_MATCH));
        if (!next) return FALSE;
        *array = next;
        *capacity = newCap;
    }

    WhoMemCopy(&(*array)[*count], m, sizeof(WHO_MATCH));
    ++(*count);
    return TRUE;
}

static UCHAR FindFileObjectTypeIndex(const WHO_HANDLE* handles,
                                     DWORD handleCount,
                                     HANDLE sentinel)
{
    DWORD self = GetCurrentProcessId();
    DWORD i;
    ULONG_PTR hv = (ULONG_PTR)sentinel;

    for (i = 0; i < handleCount; ++i) {
        if (handles[i].Pid == self &&
            handles[i].HandleValue == hv)
            return handles[i].ObjectTypeIndex;
    }

    return 0;
}


static WHO_PROCESS_CACHE* GetProcessCacheEntry(DWORD pid, HANDLE process)
{
    DWORD i;
    WHO_PROCESS_CACHE* next;
    DWORD newCap;

    for (i = 0; i < g_ProcessCacheCount; ++i)
        if (g_ProcessCache[i].Pid == pid)
            return &g_ProcessCache[i];

    if (g_ProcessCacheCount >= g_ProcessCacheCap) {
        newCap = g_ProcessCacheCap ? g_ProcessCacheCap * 2 : 64;
        if (g_ProcessCache)
            next = (WHO_PROCESS_CACHE*)HeapReAlloc(
                g_Heap, HEAP_ZERO_MEMORY, g_ProcessCache,
                newCap * sizeof(WHO_PROCESS_CACHE));
        else
            next = (WHO_PROCESS_CACHE*)HeapAlloc(
                g_Heap, HEAP_ZERO_MEMORY,
                newCap * sizeof(WHO_PROCESS_CACHE));
        if (!next) return 0;
        g_ProcessCache = next;
        g_ProcessCacheCap = newCap;
    }

    {
        WHO_PROCESS_CACHE* e = &g_ProcessCache[g_ProcessCacheCount++];
        WhoMemSet(e, 0, sizeof(*e));
        e->Pid = pid;
        e->Openable = process ? TRUE : FALSE;
        e->SessionId = QueryProcessSessionId(pid);

        if (process) {
            QueryProcessName(process, e->ProcessName,
                             sizeof(e->ProcessName) / sizeof(e->ProcessName[0]));
            QueryProcessPath(process, e->ProcessPath,
                             sizeof(e->ProcessPath) / sizeof(e->ProcessPath[0]));
            QueryProcessUser(process, e->UserName,
                             sizeof(e->UserName) / sizeof(e->UserName[0]));
        } else {
            WCopy(e->ProcessName, sizeof(e->ProcessName) / sizeof(e->ProcessName[0]),
                  L"<unknown>");
            WCopy(e->ProcessPath, sizeof(e->ProcessPath) / sizeof(e->ProcessPath[0]),
                  L"<unknown>");
            WCopy(e->UserName, sizeof(e->UserName) / sizeof(e->UserName[0]),
                  L"<unknown>");
        }

        return e;
    }
}

static void ClearProcessCache()
{
    if (g_ProcessCache) {
        HeapFree(g_Heap, 0, g_ProcessCache);
        g_ProcessCache = 0;
    }
    g_ProcessCacheCount = 0;
    g_ProcessCacheCap = 0;
}

static BOOL ProcessStemMatches(const WCHAR* actual, const WCHAR* wanted);

static BOOL FindMatches(const WCHAR* query, BOOL exact,
                        const WCHAR* processFilter,
                        BOOL usePid, DWORD pidFilter,
                        BOOL useHandle, ULONG_PTR handleFilter,
                        BOOL broadScan,
                        WHO_MATCH** outMatches, DWORD* outCount)
{
    WHO_HANDLE* handles = 0;
    DWORD handleCount = 0;
    WHO_MATCH* matches = 0;
    DWORD matchCount = 0, matchCap = 0;
    DWORD i;
    DWORD selfPid = GetCurrentProcessId();

    HANDLE sentinel = INVALID_HANDLE_VALUE;
    WCHAR module[MAX_PATH];

    *outMatches = 0;
    *outCount = 0;
    g_EnumHandleCount = 0;
    g_OpenProcessCount = 0;
    g_DuplicateCount = 0;
    g_DiskHandleCount = 0;
    g_NameCount = 0;
    g_FileInfoTimeoutCount = 0;
    g_NameTimeoutCount = 0;
    g_FileTypeIndex = 0;
    ClearProcessCache();

    // Open a known disk File object BEFORE taking the handle snapshot.
    module[0] = 0;
    if (GetModuleFileNameW(0, module, MAX_PATH)) {
        sentinel = CreateFileW(module, 0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    }

    if (!EnumerateSystemHandles(&handles, &handleCount)) {
        if (sentinel != INVALID_HANDLE_VALUE) CloseHandle(sentinel);
        return FALSE;
    }

    g_EnumHandleCount = handleCount;

    {
        UCHAR fileTypeIndex = 0;
        if (sentinel != INVALID_HANDLE_VALUE)
            fileTypeIndex = FindFileObjectTypeIndex(handles, handleCount, sentinel);
        g_FileTypeIndex = fileTypeIndex;

        if (sentinel != INVALID_HANDLE_VALUE) {
            CloseHandle(sentinel);
            sentinel = INVALID_HANDLE_VALUE;
        }

        // For substring searches we must resolve names with NtQueryObject, so
        // we require a trustworthy File object type filter. Exact searches use
        // GetFileInformationByHandle instead and can safely proceed without it.
        if (fileTypeIndex == 0 && !exact) {
            HeapFree(g_Heap, 0, handles);
            return FALSE;
        }

        for (i = 0; i < handleCount; ++i) {
            if (fileTypeIndex != 0 && handles[i].ObjectTypeIndex != fileTypeIndex)
                continue;
        HANDLE process;
        HANDLE dup = 0;
        BOOL leakDup = FALSE;
        DWORD access = PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

        if (handles[i].Pid == selfPid) continue;

        // Apply cheap owner/handle filters before DuplicateHandle and before
        // the potentially slow native file-name query.
        if (usePid && handles[i].Pid != pidFilter)
            continue;
        if (useHandle && handles[i].HandleValue != handleFilter)
            continue;

        process = OpenProcess(access, FALSE, handles[i].Pid);
        if (!process) {
            access = PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION;
            process = OpenProcess(access, FALSE, handles[i].Pid);
        }
        if (!process) continue;
        ++g_OpenProcessCount;

        {
            WHO_PROCESS_CACHE* pc = GetProcessCacheEntry(handles[i].Pid, process);

            if (processFilter) {
                if (!pc || !ProcessStemMatches(pc->ProcessName, processFilter)) {
                    CloseHandle(process);
                    continue;
                }
            }
        }

        if (!DuplicateHandle(process, (HANDLE)handles[i].HandleValue,
                             GetCurrentProcess(), &dup, 0, FALSE,
                             DUPLICATE_SAME_ACCESS)) {
            CloseHandle(process);
            continue;
        }
        ++g_DuplicateCount;

        {
            BOOL hit = FALSE;

            if (exact && g_TargetInfoValid) {
                int identity = SameFileIdentityTimed(dup, &g_TargetInfo, 2);
                if (identity == 1) {
                    hit = TRUE;
                    WCopy(g_PathScratch,
                          sizeof(g_PathScratch) / sizeof(g_PathScratch[0]),
                          query);
                } else if (identity == 2) {
                    leakDup = TRUE;
                }
            } else {
                int nameResult = QueryHandleDosPathTimed(
                    dup, g_PathScratch,
                    sizeof(g_PathScratch) / sizeof(g_PathScratch[0]), 5);

                if (nameResult == 1) {
                    ++g_NameCount;
                    hit = NameCriterionMatches(query, g_PathScratch);
                } else if (nameResult == 2) {
                    leakDup = TRUE;
                }
            }

            if (hit) {
                WhoMemSet(&g_TempMatch, 0, sizeof(g_TempMatch));
                g_TempMatch.Pid = handles[i].Pid;
                g_TempMatch.HandleValue = handles[i].HandleValue;
                {
                    WHO_PROCESS_CACHE* pc = GetProcessCacheEntry(handles[i].Pid, process);

                    g_TempMatch.SessionId =
                        pc ? pc->SessionId : QueryProcessSessionId(handles[i].Pid);
                    WCopy(g_TempMatch.Path,
                          sizeof(g_TempMatch.Path) / sizeof(g_TempMatch.Path[0]),
                          g_PathScratch);

                    if (pc) {
                        WCopy(g_TempMatch.ProcessName,
                              sizeof(g_TempMatch.ProcessName) /
                              sizeof(g_TempMatch.ProcessName[0]),
                              pc->ProcessName);
                        WCopy(g_TempMatch.ProcessPath,
                              sizeof(g_TempMatch.ProcessPath) /
                              sizeof(g_TempMatch.ProcessPath[0]),
                              pc->ProcessPath);
                        WCopy(g_TempMatch.UserName,
                              sizeof(g_TempMatch.UserName) /
                              sizeof(g_TempMatch.UserName[0]),
                              pc->UserName);
                    } else {
                        QueryProcessName(process, g_TempMatch.ProcessName,
                                         sizeof(g_TempMatch.ProcessName) /
                                         sizeof(g_TempMatch.ProcessName[0]));
                        QueryProcessPath(process, g_TempMatch.ProcessPath,
                                         sizeof(g_TempMatch.ProcessPath) /
                                         sizeof(g_TempMatch.ProcessPath[0]));
                        QueryProcessUser(process, g_TempMatch.UserName,
                                         sizeof(g_TempMatch.UserName) /
                                         sizeof(g_TempMatch.UserName[0]));
                    }
                }
                QueryTargetType(g_TempMatch.Path, g_TempMatch.TargetType,
                                sizeof(g_TempMatch.TargetType) / sizeof(g_TempMatch.TargetType[0]));
                if (broadScan)
                    WCopy(g_TempMatch.LockHint,
                          sizeof(g_TempMatch.LockHint) / sizeof(g_TempMatch.LockHint[0]),
                          L"unknown");
                else
                    QueryLockHint(g_TempMatch.Path, g_TempMatch.LockHint,
                                  sizeof(g_TempMatch.LockHint) / sizeof(g_TempMatch.LockHint[0]));
                if (!AddMatch(&matches, &matchCount, &matchCap, &g_TempMatch)) {
                    if (!leakDup) CloseHandle(dup);
                    CloseHandle(process);
                    HeapFree(g_Heap, 0, handles);
                    if (matches) HeapFree(g_Heap, 0, matches);
                    return FALSE;
                }
            }
        }

        if (!leakDup) CloseHandle(dup);
        CloseHandle(process);
        }
    }

    HeapFree(g_Heap, 0, handles);
    ClearProcessCache();
    *outMatches = matches;
    *outCount = matchCount;
    return TRUE;
}

// Re-check the handle before closing it, reducing the chance of closing a recycled handle.
static BOOL CloseVerifiedHandle(const WHO_MATCH* m, const WCHAR* exactPath)
{
    HANDLE process;
    HANDLE verify = 0;
    HANDLE closeCopy = 0;
    BOOL same = FALSE;

    process = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                          FALSE, m->Pid);
    if (!process) return FALSE;

    if (DuplicateHandle(process, (HANDLE)m->HandleValue,
                        GetCurrentProcess(), &verify, 0, FALSE,
                        DUPLICATE_SAME_ACCESS)) {
        int qr = QueryHandleDosPathTimed(
            verify, g_VerifyPath,
            sizeof(g_VerifyPath) / sizeof(g_VerifyPath[0]), 5);

        if (qr == 1)
            same = WEqualI(g_VerifyPath, exactPath);

        // If the query timed out, the worker may still reference verify.
        if (qr != 2)
            CloseHandle(verify);
    }

    if (!same) {
        CloseHandle(process);
        return FALSE;
    }

    if (!DuplicateHandle(process, (HANDLE)m->HandleValue,
                         GetCurrentProcess(), &closeCopy, 0, FALSE,
                         DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE)) {
        CloseHandle(process);
        return FALSE;
    }

    CloseHandle(closeCopy);
    CloseHandle(process);
    return TRUE;
}

// ----- UI -----

static void PrintUsage()
{
    OutLn(L"who [target] [/a] [/i image] [/d pid] [/h handle]");
    OutLn(L"    [/y] [/z] [/p] [/c|/t|/u] [/f]");
    OutLn(L"who /?");
    OutLn(L"who /v");
    OutLn(L"");
    OutLn(L"Search scope:");
    OutLn(L"  default             matching items in current directory only");
    OutLn(L"  /a                  search matching live open handles system-wide");
    OutLn(L"");
    OutLn(L"Examples:");
    OutLn(L"  who d*");
    OutLn(L"  who d*/a");
    OutLn(L"  who /a d*");
    OutLn(L"  who /i chrome*");
    OutLn(L"  who /a/i chrome*");
    OutLn(L"  who /d6096");
    OutLn(L"  who /a/d6096");
    OutLn(L"  who \\somewhere\\my file/c");
    OutLn(L"");
    OutLn(L"Display:");
    OutLn(L"  /y                  show full process image path");
    OutLn(L"  /z                  show full file/directory path");
    OutLn(L"");
    OutLn(L"Filters/actions:");
    OutLn(L"  /i image            image name/pattern; .exe optional");
    OutLn(L"  /d pid              process ID");
    OutLn(L"  /p                  pause output when the console screen fills");
    OutLn(L"  /h handle           handle value");
    OutLn(L"  /c                  close selected file handle(s)");
    OutLn(L"  /t                  terminate selected owning process(es)");
    OutLn(L"  /u                  terminate selected user account process(es)");
    OutLn(L"  /f                  force: skip Y/N confirmation");
    OutLn(L"");
    OutLn(L"Only '/' introduces an option. Option values may be attached or");
    OutLn(L"space-separated; spaces inside /i values do not require quotes.");
}

static BOOL IsOpt(const WCHAR* s, WCHAR ch)
{
    WCHAR slash[3] = { L'/', ch, 0 };
    return WEqualI(s, slash);
}

static SIZE_T MaxSize(SIZE_T a, SIZE_T b)
{
    return a > b ? a : b;
}

static void FillChars(WCHAR* out, SIZE_T cap, WCHAR ch, SIZE_T count)
{
    SIZE_T i;
    if (!out || cap == 0) return;
    if (count + 1 > cap) count = cap - 1;
    for (i = 0; i < count; ++i) out[i] = ch;
    out[count] = 0;
}

static SIZE_T ConsoleWindowColumns()
{
    CONSOLE_SCREEN_BUFFER_INFO ci;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);

    if (h == INVALID_HANDLE_VALUE)
        return 0;

    if (!GetConsoleScreenBufferInfo(h, &ci))
        return 0;

    if (ci.srWindow.Right < ci.srWindow.Left)
        return 0;

    return (SIZE_T)(ci.srWindow.Right - ci.srWindow.Left + 1);
}

static void AppendColumnGap(WCHAR* line, SIZE_T cap, BOOL addSeparator)
{
    SIZE_T cols, used, room, wanted;

    if (!addSeparator)
        return;

    wanted = 4;
    cols = ConsoleWindowColumns();
    used = WLen(line);

    /*
      Never let separator padding alone wrap onto the next console line.
      If fewer than four spaces remain, emit only the spaces that still fit.
    */
    if (cols && used < cols) {
        room = cols - used;
        if (wanted > room)
            wanted = room;
    } else if (cols && used >= cols) {
        wanted = 0;
    }

    while (wanted--)
        WCat(line, cap, L" ");
}

static void AppendColumn(WCHAR* line, SIZE_T cap,
                         const WCHAR* value, SIZE_T width,
                         BOOL addSeparator)
{
    AppendField(line, cap, value, width);
    AppendColumnGap(line, cap, addSeparator);
}

static void AppendFieldSlice(WCHAR* line, SIZE_T cap,
                             const WCHAR* value,
                             SIZE_T offset,
                             SIZE_T width)
{
    SIZE_T n, i, remain, take;

    if (!value) value = L"";
    if (width == 0) return;

    n = WLen(value);
    if (offset >= n) {
        for (i = 0; i < width; ++i)
            WCat(line, cap, L" ");
        return;
    }

    remain = n - offset;
    take = remain < width ? remain : width;

    for (i = 0; i < take; ++i) {
        WCHAR one[2];
        one[0] = value[offset + i];
        one[1] = 0;
        WCat(line, cap, one);
    }

    for (i = take; i < width; ++i)
        WCat(line, cap, L" ");
}

static void AppendSeparatorColumn(WCHAR* line, SIZE_T cap,
                                  SIZE_T width, BOOL addSeparator)
{
    FillChars(g_ChunkScratch,
              sizeof(g_ChunkScratch) / sizeof(g_ChunkScratch[0]),
              L'-', width);
    WCat(line, cap, g_ChunkScratch);
    AppendColumnGap(line, cap, addSeparator);
}

static DWORD ConsolePageRows()
{
    CONSOLE_SCREEN_BUFFER_INFO ci;
    HANDLE h;

    if (!g_PauseOutput)
        return 0;

    h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(h, &ci))
        return 0;

    {
        SHORT rows = (SHORT)(ci.srWindow.Bottom - ci.srWindow.Top + 1);
        if (rows <= 2)
            return 0;
        return (DWORD)(rows - 1);
    }
}

static void PauseForMore()
{
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldMode = 0, read = 0;
    INPUT_RECORD rec;

    if (!GetConsoleMode(in, &oldMode))
        return;

    Out(L"-- More --  (press any key)");
    for (;;) {
        if (!ReadConsoleInputW(in, &rec, 1, &read) || !read)
            break;
        if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown)
            break;
    }
    Out(L"\r                              \r");
}



static SIZE_T CompactContentWidth(SIZE_T columnWidth)
{
    if (columnWidth > 4)
        return columnWidth - 4;
    return 1;
}

static void AppendCompactCellSlice(WCHAR* line, SIZE_T cap,
                                   const WCHAR* value,
                                   SIZE_T offset,
                                   SIZE_T columnWidth,
                                   BOOL lastColumn)
{
    SIZE_T contentWidth = CompactContentWidth(columnWidth);
    SIZE_T n = WLen(value ? value : L"");
    SIZE_T i, take = 0;

    if (!value) value = L"";

    if (offset < n) {
        take = n - offset;
        if (take > contentWidth)
            take = contentWidth;
    }

    for (i = 0; i < take; ++i) {
        WCHAR one[2];
        one[0] = value[offset + i];
        one[1] = 0;
        WCat(line, cap, one);
    }

    /* Pad the content area. */
    for (i = take; i < contentWidth; ++i)
        WCat(line, cap, L" ");

    if (!lastColumn) {
        /*
          Four spaces belong to the column. They are emitted only when they
          still fit inside the visible console row; the width allocator below
          normally guarantees that they do.
        */
        for (i = 0; i < 4; ++i)
            WCat(line, cap, L" ");
    }
}

static SIZE_T CompactSliceCount(const WCHAR* value, SIZE_T columnWidth)
{
    SIZE_T n = WLen(value ? value : L"");
    SIZE_T contentWidth = CompactContentWidth(columnWidth);

    if (!n)
        return 1;

    return (n + contentWidth - 1) / contentWidth;
}

static void OutLnNoDoubleWrap(const WCHAR* text);

static void PrintCompactHeader(const SIZE_T* widths)
{
    static const WCHAR* names[8] = {
        L"Process", L"PID", L"Session", L"User",
        L"Handle", L"Type", L"State", L"Target"
    };
    DWORD i;
    SIZE_T j;

    g_LineScratch[0] = 0;

    for (i = 0; i < 8; ++i) {
        SIZE_T contentWidth = CompactContentWidth(widths[i]);
        SIZE_T n = WLen(names[i]);

        WCat(g_LineScratch,
             sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
             names[i]);

        for (j = n; j < contentWidth; ++j)
            WCat(g_LineScratch,
                 sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                 L" ");

        if (i != 7) {
            for (j = 0; j < 4; ++j)
                WCat(g_LineScratch,
                     sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                     L" ");
        }
    }

    OutLnNoDoubleWrap(g_LineScratch);

    g_SeparatorScratch[0] = 0;

    for (i = 0; i < 8; ++i) {
        SIZE_T dashCount;

        /*
          Separator occupies the full column except its last character,
          which is the single visible gap between separator segments.
        */
        dashCount = (widths[i] > 1) ? widths[i] - 1 : 1;

        for (j = 0; j < dashCount; ++j)
            WCat(g_SeparatorScratch,
                 sizeof(g_SeparatorScratch) /
                 sizeof(g_SeparatorScratch[0]),
                 L"-");

        if (i != 7)
            WCat(g_SeparatorScratch,
                 sizeof(g_SeparatorScratch) /
                 sizeof(g_SeparatorScratch[0]),
                 L" ");
    }

    OutLnNoDoubleWrap(g_SeparatorScratch);
}

static void AllocateCompactWidths(SIZE_T* widths,
                                  const SIZE_T* desired,
                                  const SIZE_T* minimum)
{
    SIZE_T cols = ConsoleWindowColumns();
    SIZE_T total = 0;
    SIZE_T i;

    for (i = 0; i < 8; ++i) {
        widths[i] = desired[i];
        total += widths[i];
    }

    if (!cols || total <= cols)
        return;

    /*
      Reduce the column that currently has the most room above its minimum.
      This keeps every column as wide as possible while guaranteeing that the
      complete aligned row fits in the current console window.
    */
    while (total > cols) {
        SIZE_T best = 8;
        SIZE_T bestSlack = 0;

        for (i = 0; i < 8; ++i) {
            SIZE_T slack =
                (widths[i] > minimum[i]) ?
                (widths[i] - minimum[i]) : 0;

            if (slack > bestSlack) {
                bestSlack = slack;
                best = i;
            }
        }

        if (best == 8 || bestSlack == 0)
            break;

        --widths[best];
        --total;
    }
}


static void CopyLineChunk(WCHAR* dst, SIZE_T dstCap,
                          const WCHAR* src, SIZE_T offset, SIZE_T count)
{
    SIZE_T i = 0;

    if (!dst || dstCap == 0)
        return;

    while (i < count && src[offset + i] && i + 1 < dstCap) {
        dst[i] = src[offset + i];
        ++i;
    }

    /*
      Trailing spaces are not useful at the right edge and can themselves
      trigger an extra console wrap on old Windows consoles.
    */
    while (i && dst[i - 1] == L' ')
        --i;

    dst[i] = 0;
}


static void OutLnNoDoubleWrap(const WCHAR* text)
{
    SIZE_T cols = ConsoleWindowColumns();
    SIZE_T len = WLen(text);

    if (!cols || len == 0 || (len % cols) != 0) {
        OutLn(text);
        return;
    }

    /*
      On the classic Windows console, writing the last character into the
      rightmost visible column already advances the cursor to the next row
      when ENABLE_WRAP_AT_EOL_OUTPUT is active.

      Therefore DO NOT emit CR/LF here.  Doing so advances a second time and
      creates the blank row seen between:
          header -> separator
      and:
          separator -> first data row

      This special case is used only by header/separator rendering.
    */
    Out(text);
}
static void PrintWrappedHeaderAndRule(const WCHAR* header,
                                      const WCHAR* rule)
{
    SIZE_T cols = ConsoleWindowColumns();
    SIZE_T headerLen = WLen(header);
    SIZE_T ruleLen = WLen(rule);
    SIZE_T maxLen = MaxSize(headerLen, ruleLen);
    SIZE_T offset = 0;

    if (!cols || maxLen <= cols) {
        OutLnNoDoubleWrap(header);
        OutLnNoDoubleWrap(rule);
        return;
    }

    while (offset < maxLen) {
        SIZE_T take = cols;

        if (take >= sizeof(g_ChunkScratch) / sizeof(g_ChunkScratch[0]))
            take = (sizeof(g_ChunkScratch) / sizeof(g_ChunkScratch[0])) - 1;

        if (offset < headerLen) {
            CopyLineChunk(g_ChunkScratch,
                          sizeof(g_ChunkScratch) / sizeof(g_ChunkScratch[0]),
                          header, offset, take);
            OutLnNoDoubleWrap(g_ChunkScratch);
        }

        if (offset < ruleLen) {
            CopyLineChunk(g_ChunkScratch,
                          sizeof(g_ChunkScratch) / sizeof(g_ChunkScratch[0]),
                          rule, offset, take);
            OutLnNoDoubleWrap(g_ChunkScratch);
        }

        offset += cols;
    }
}


static void AppendFullHeaderRuleColumn(WCHAR* dst, SIZE_T cap,
                                       SIZE_T contentWidth,
                                       BOOL lastColumn)
{
    SIZE_T effectiveWidth;
    SIZE_T dashCount;
    SIZE_T i;

    if (lastColumn) {
        /*
          Final column has no trailing four-space data gap.
          Its underline is simply its content width.
        */
        dashCount = contentWidth ? contentWidth : 1;
    } else {
        effectiveWidth = contentWidth + 4;
        dashCount = effectiveWidth - 1;
    }

    for (i = 0; i < dashCount; ++i)
        WCat(dst, cap, L"-");

    if (!lastColumn)
        WCat(dst, cap, L" ");
}


static void AppendFullColumn(WCHAR* line, SIZE_T cap,
                             const WCHAR* value, SIZE_T width,
                             BOOL addSeparator)
{
    SIZE_T i;

    AppendField(line, cap, value, width);

    if (addSeparator) {
        for (i = 0; i < 4; ++i)
            WCat(line, cap, L" ");
    }
}

static void PrintMatchHeader(SIZE_T processWidth,
                             SIZE_T pidWidth,
                             SIZE_T sessionWidth,
                             SIZE_T userWidth,
                             SIZE_T handleWidth,
                             SIZE_T typeWidth,
                             SIZE_T stateWidth,
                             SIZE_T imageWidth,
                             SIZE_T targetWidth,
                             const SIZE_T* compactWidths)
{
    if (!g_ShowImagePath && !g_ShowFullPath) {
        PrintCompactHeader(compactWidths);
        return;
    }

    g_LineScratch[0] = 0;
    AppendFullColumn(g_LineScratch, sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                 L"Process", processWidth, TRUE);
    AppendFullColumn(g_LineScratch, sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                 L"PID", pidWidth, TRUE);
    AppendFullColumn(g_LineScratch, sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                 L"Session", sessionWidth, TRUE);
    AppendFullColumn(g_LineScratch, sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                 L"User", userWidth, TRUE);
    AppendFullColumn(g_LineScratch, sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                 L"Handle", handleWidth, TRUE);
    AppendFullColumn(g_LineScratch, sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                 L"Type", typeWidth, TRUE);
    AppendFullColumn(g_LineScratch, sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                 L"State", stateWidth, TRUE);
    if (g_ShowImagePath)
        AppendFullColumn(g_LineScratch, sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                     L"ImagePath", imageWidth, TRUE);
    AppendFullColumn(g_LineScratch, sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                 g_ShowFullPath ? L"FilePath" : L"Target", targetWidth, FALSE);

    g_SeparatorScratch[0] = 0;

    AppendFullHeaderRuleColumn(
        g_SeparatorScratch,
        sizeof(g_SeparatorScratch) / sizeof(g_SeparatorScratch[0]),
        processWidth, FALSE);
    AppendFullHeaderRuleColumn(
        g_SeparatorScratch,
        sizeof(g_SeparatorScratch) / sizeof(g_SeparatorScratch[0]),
        pidWidth, FALSE);
    AppendFullHeaderRuleColumn(
        g_SeparatorScratch,
        sizeof(g_SeparatorScratch) / sizeof(g_SeparatorScratch[0]),
        sessionWidth, FALSE);
    AppendFullHeaderRuleColumn(
        g_SeparatorScratch,
        sizeof(g_SeparatorScratch) / sizeof(g_SeparatorScratch[0]),
        userWidth, FALSE);
    AppendFullHeaderRuleColumn(
        g_SeparatorScratch,
        sizeof(g_SeparatorScratch) / sizeof(g_SeparatorScratch[0]),
        handleWidth, FALSE);
    AppendFullHeaderRuleColumn(
        g_SeparatorScratch,
        sizeof(g_SeparatorScratch) / sizeof(g_SeparatorScratch[0]),
        typeWidth, FALSE);
    AppendFullHeaderRuleColumn(
        g_SeparatorScratch,
        sizeof(g_SeparatorScratch) / sizeof(g_SeparatorScratch[0]),
        stateWidth, FALSE);

    if (g_ShowImagePath) {
        AppendFullHeaderRuleColumn(
            g_SeparatorScratch,
            sizeof(g_SeparatorScratch) / sizeof(g_SeparatorScratch[0]),
            imageWidth, FALSE);
    }

    AppendFullHeaderRuleColumn(
        g_SeparatorScratch,
        sizeof(g_SeparatorScratch) / sizeof(g_SeparatorScratch[0]),
        targetWidth, TRUE);

    PrintWrappedHeaderAndRule(g_LineScratch, g_SeparatorScratch);
}


static void ComputeFullPageWidths(const WHO_MATCH* m,
                                  DWORD startIndex,
                                  DWORD endIndex,
                                  SIZE_T* processWidth,
                                  SIZE_T* pidWidth,
                                  SIZE_T* sessionWidth,
                                  SIZE_T* userWidth,
                                  SIZE_T* handleWidth,
                                  SIZE_T* typeWidth,
                                  SIZE_T* stateWidth,
                                  SIZE_T* imageWidth,
                                  SIZE_T* targetWidth)
{
    DWORD i;
    WCHAR pid[32], hv[32], sess[32];
    const WCHAR* target;
    SIZE_T longestTarget;
    SIZE_T cols;
    SIZE_T usedBeforeTarget;
    SIZE_T remaining;

    *processWidth = WLen(L"Process");
    *pidWidth = WLen(L"PID");
    *sessionWidth = WLen(L"Session");
    *userWidth = WLen(L"User");
    *handleWidth = WLen(L"Handle");
    *typeWidth = WLen(L"Type");
    *stateWidth = WLen(L"State");
    *imageWidth = WLen(L"ImagePath");
    *targetWidth = WLen(g_ShowFullPath ? L"FilePath" : L"Target");

    longestTarget = *targetWidth;

    for (i = startIndex; i < endIndex; ++i) {
        UIntToDec(m[i].Pid, pid, sizeof(pid) / sizeof(pid[0]));
        UIntPtrToHex(m[i].HandleValue, hv, sizeof(hv) / sizeof(hv[0]));

        if (m[i].SessionId == 0xFFFFFFFFUL)
            WCopy(sess, sizeof(sess) / sizeof(sess[0]), L"?");
        else
            UIntToDec(m[i].SessionId, sess, sizeof(sess) / sizeof(sess[0]));

        target = g_ShowFullPath ? m[i].Path : BaseNamePtr(m[i].Path);

        *processWidth = MaxSize(*processWidth, WLen(m[i].ProcessName));
        *pidWidth = MaxSize(*pidWidth, WLen(pid));
        *sessionWidth = MaxSize(*sessionWidth, WLen(sess));
        *userWidth = MaxSize(*userWidth, WLen(m[i].UserName));
        *handleWidth = MaxSize(*handleWidth, WLen(hv));
        *typeWidth = MaxSize(*typeWidth, WLen(m[i].TargetType));
        *stateWidth = MaxSize(*stateWidth, WLen(m[i].LockHint));

        if (g_ShowImagePath)
            *imageWidth = MaxSize(*imageWidth, WLen(m[i].ProcessPath));

        longestTarget = MaxSize(longestTarget, WLen(target));
    }

    cols = ConsoleWindowColumns();

    if (!cols) {
        *targetWidth = longestTarget;
        return;
    }

    usedBeforeTarget =
        (*processWidth + 4) +
        (*pidWidth + 4) +
        (*sessionWidth + 4) +
        (*userWidth + 4) +
        (*handleWidth + 4) +
        (*typeWidth + 4) +
        (*stateWidth + 4);

    if (g_ShowImagePath)
        usedBeforeTarget += (*imageWidth + 4);

    if (usedBeforeTarget >= cols) {
        remaining = cols;
    } else {
        remaining = cols - usedBeforeTarget;
    }

    if (remaining < WLen(g_ShowFullPath ? L"FilePath" : L"Target"))
        remaining = WLen(g_ShowFullPath ? L"FilePath" : L"Target");

    *targetWidth = longestTarget;
    if (*targetWidth > remaining)
        *targetWidth = remaining;
}

static void PrintMatches(const WHO_MATCH* m, DWORD count)
{
    DWORD i;
    SIZE_T processWidth = WLen(L"Process");
    SIZE_T pidWidth = WLen(L"PID");
    SIZE_T sessionWidth = WLen(L"Session");
    SIZE_T userWidth = WLen(L"User");
    SIZE_T handleWidth = WLen(L"Handle");
    SIZE_T typeWidth = WLen(L"Type");
    SIZE_T stateWidth = WLen(L"State");
    SIZE_T imageWidth = WLen(L"ImagePath");
    SIZE_T targetWidth = WLen(g_ShowFullPath ? L"FilePath" : L"Target");
    SIZE_T compactDesired[8];
    SIZE_T compactMinimum[8];
    SIZE_T compactWidths[8];
    WCHAR pid[32], hv[32], sess[32];
    const WCHAR* target;
    DWORD pageRows = ConsolePageRows();
    DWORD rowsOnPage = 2; /* header + separator */
    DWORD fullPageStart = 0;
    DWORD fullPageEnd = count;
    DWORD fullPageCapacity = 0;

    static const WCHAR* compactHeaders[8] = {
        L"Process", L"PID", L"Session", L"User",
        L"Handle", L"Type", L"State", L"Target"
    };

    for (i = 0; i < 8; ++i) {
        compactDesired[i] = WLen(compactHeaders[i]) + 4;
        compactMinimum[i] = WLen(compactHeaders[i]) + 4;
        compactWidths[i] = compactDesired[i];
    }

    /*
      First pass: determine the natural maximum value length of every column.
      Four spaces are part of each compact column.  This gives the ideal,
      fully-aligned table if it fits in the visible console.
    */
    for (i = 0; i < count; ++i) {
        UIntToDec(m[i].Pid, pid, sizeof(pid) / sizeof(pid[0]));
        UIntPtrToHex(m[i].HandleValue, hv, sizeof(hv) / sizeof(hv[0]));

        if (m[i].SessionId == 0xFFFFFFFFUL)
            WCopy(sess, sizeof(sess) / sizeof(sess[0]), L"?");
        else
            UIntToDec(m[i].SessionId, sess, sizeof(sess) / sizeof(sess[0]));

        target = g_ShowFullPath ? m[i].Path : BaseNamePtr(m[i].Path);

        processWidth = MaxSize(processWidth, WLen(m[i].ProcessName));
        pidWidth = MaxSize(pidWidth, WLen(pid));
        sessionWidth = MaxSize(sessionWidth, WLen(sess));
        userWidth = MaxSize(userWidth, WLen(m[i].UserName));
        handleWidth = MaxSize(handleWidth, WLen(hv));
        typeWidth = MaxSize(typeWidth, WLen(m[i].TargetType));
        stateWidth = MaxSize(stateWidth, WLen(m[i].LockHint));

        if (g_ShowImagePath)
            imageWidth = MaxSize(imageWidth, WLen(m[i].ProcessPath));

        targetWidth = MaxSize(targetWidth, WLen(target));

        if (!g_ShowImagePath && !g_ShowFullPath) {
            compactDesired[0] =
                MaxSize(compactDesired[0], WLen(m[i].ProcessName) + 4);
            compactDesired[1] =
                MaxSize(compactDesired[1], WLen(pid) + 4);
            compactDesired[2] =
                MaxSize(compactDesired[2], WLen(sess) + 4);
            compactDesired[3] =
                MaxSize(compactDesired[3], WLen(m[i].UserName) + 4);
            compactDesired[4] =
                MaxSize(compactDesired[4], WLen(hv) + 4);
            compactDesired[5] =
                MaxSize(compactDesired[5], WLen(m[i].TargetType) + 4);
            compactDesired[6] =
                MaxSize(compactDesired[6], WLen(m[i].LockHint) + 4);
            compactDesired[7] =
                MaxSize(compactDesired[7], WLen(target) + 4);
        }
    }

    if (!g_ShowImagePath && !g_ShowFullPath) {
        AllocateCompactWidths(compactWidths, compactDesired, compactMinimum);
    } else if (pageRows) {
        /*
          In full-path mode with /p, size the columns from the rows that will
          appear on this screen, not from the entire result set.
        */
        fullPageCapacity = (pageRows > 3) ? (pageRows - 3) : 1;
        fullPageEnd = fullPageStart + fullPageCapacity;
        if (fullPageEnd > count)
            fullPageEnd = count;

        ComputeFullPageWidths(m, fullPageStart, fullPageEnd,
                              &processWidth, &pidWidth, &sessionWidth,
                              &userWidth, &handleWidth, &typeWidth,
                              &stateWidth, &imageWidth, &targetWidth);
    } else if (g_ShowImagePath || g_ShowFullPath) {
        /*
          Non-paged full output keeps global widths. Size the final
          FilePath/Target rule to the visible remainder of the console, capped
          by the longest target found in the result set.
        */
        {
            SIZE_T cols = ConsoleWindowColumns();
            SIZE_T usedBeforeTarget =
                (processWidth + 4) +
                (pidWidth + 4) +
                (sessionWidth + 4) +
                (userWidth + 4) +
                (handleWidth + 4) +
                (typeWidth + 4) +
                (stateWidth + 4);
            SIZE_T remaining;

            if (g_ShowImagePath)
                usedBeforeTarget += (imageWidth + 4);

            if (cols) {
                remaining = (usedBeforeTarget >= cols) ?
                            cols : (cols - usedBeforeTarget);

                if (remaining <
                    WLen(g_ShowFullPath ? L"FilePath" : L"Target"))
                    remaining =
                        WLen(g_ShowFullPath ? L"FilePath" : L"Target");

                if (targetWidth > remaining)
                    targetWidth = remaining;
            }
        }
    }

    PrintMatchHeader(processWidth, pidWidth, sessionWidth, userWidth,
                     handleWidth, typeWidth, stateWidth, imageWidth,
                     targetWidth, compactWidths);

    for (i = 0; i < count; ++i) {
        SIZE_T physicalLines = 1;
        SIZE_T lineNo;

        UIntToDec(m[i].Pid, pid, sizeof(pid) / sizeof(pid[0]));
        UIntPtrToHex(m[i].HandleValue, hv, sizeof(hv) / sizeof(hv[0]));

        if (m[i].SessionId == 0xFFFFFFFFUL)
            WCopy(sess, sizeof(sess) / sizeof(sess[0]), L"?");
        else
            UIntToDec(m[i].SessionId, sess, sizeof(sess) / sizeof(sess[0]));

        target = g_ShowFullPath ? m[i].Path : BaseNamePtr(m[i].Path);

        if (!g_ShowImagePath && !g_ShowFullPath) {
            physicalLines = MaxSize(
                physicalLines,
                CompactSliceCount(m[i].ProcessName, compactWidths[0]));
            physicalLines = MaxSize(
                physicalLines,
                CompactSliceCount(pid, compactWidths[1]));
            physicalLines = MaxSize(
                physicalLines,
                CompactSliceCount(sess, compactWidths[2]));
            physicalLines = MaxSize(
                physicalLines,
                CompactSliceCount(m[i].UserName, compactWidths[3]));
            physicalLines = MaxSize(
                physicalLines,
                CompactSliceCount(hv, compactWidths[4]));
            physicalLines = MaxSize(
                physicalLines,
                CompactSliceCount(m[i].TargetType, compactWidths[5]));
            physicalLines = MaxSize(
                physicalLines,
                CompactSliceCount(m[i].LockHint, compactWidths[6]));
            physicalLines = MaxSize(
                physicalLines,
                CompactSliceCount(target, compactWidths[7]));
        }

        for (lineNo = 0; lineNo < physicalLines; ++lineNo) {
            if (pageRows && rowsOnPage >= pageRows) {
                PauseForMore();
                OutLn(L"");

                if (g_ShowImagePath || g_ShowFullPath) {
                    fullPageStart = i;
                    fullPageEnd = fullPageStart + fullPageCapacity;
                    if (fullPageEnd > count)
                        fullPageEnd = count;

                    ComputeFullPageWidths(m, fullPageStart, fullPageEnd,
                                          &processWidth, &pidWidth,
                                          &sessionWidth, &userWidth,
                                          &handleWidth, &typeWidth,
                                          &stateWidth, &imageWidth,
                                          &targetWidth);
                }

                PrintMatchHeader(processWidth, pidWidth, sessionWidth, userWidth,
                                 handleWidth, typeWidth, stateWidth, imageWidth,
                                 targetWidth, compactWidths);
                rowsOnPage = 3; /* blank + header + separator */
            }

            g_LineScratch[0] = 0;

            if (!g_ShowImagePath && !g_ShowFullPath) {
                AppendCompactCellSlice(
                    g_LineScratch,
                    sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                    m[i].ProcessName,
                    lineNo * CompactContentWidth(compactWidths[0]),
                    compactWidths[0],
                    FALSE);

                AppendCompactCellSlice(
                    g_LineScratch,
                    sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                    pid,
                    lineNo * CompactContentWidth(compactWidths[1]),
                    compactWidths[1],
                    FALSE);

                AppendCompactCellSlice(
                    g_LineScratch,
                    sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                    sess,
                    lineNo * CompactContentWidth(compactWidths[2]),
                    compactWidths[2],
                    FALSE);

                AppendCompactCellSlice(
                    g_LineScratch,
                    sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                    m[i].UserName,
                    lineNo * CompactContentWidth(compactWidths[3]),
                    compactWidths[3],
                    FALSE);

                AppendCompactCellSlice(
                    g_LineScratch,
                    sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                    hv,
                    lineNo * CompactContentWidth(compactWidths[4]),
                    compactWidths[4],
                    FALSE);

                AppendCompactCellSlice(
                    g_LineScratch,
                    sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                    m[i].TargetType,
                    lineNo * CompactContentWidth(compactWidths[5]),
                    compactWidths[5],
                    FALSE);

                AppendCompactCellSlice(
                    g_LineScratch,
                    sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                    m[i].LockHint,
                    lineNo * CompactContentWidth(compactWidths[6]),
                    compactWidths[6],
                    FALSE);

                AppendCompactCellSlice(
                    g_LineScratch,
                    sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                    target,
                    lineNo * CompactContentWidth(compactWidths[7]),
                    compactWidths[7],
                    TRUE);
            } else {
                AppendFullColumn(g_LineScratch,
                             sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                             m[i].ProcessName, processWidth, TRUE);
                AppendFullColumn(g_LineScratch,
                             sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                             pid, pidWidth, TRUE);
                AppendFullColumn(g_LineScratch,
                             sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                             sess, sessionWidth, TRUE);
                AppendFullColumn(g_LineScratch,
                             sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                             m[i].UserName, userWidth, TRUE);
                AppendFullColumn(g_LineScratch,
                             sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                             hv, handleWidth, TRUE);
                AppendFullColumn(g_LineScratch,
                             sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                             m[i].TargetType, typeWidth, TRUE);
                AppendFullColumn(g_LineScratch,
                             sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                             m[i].LockHint, stateWidth, TRUE);

                if (g_ShowImagePath)
                    AppendFullColumn(g_LineScratch,
                                 sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                                 m[i].ProcessPath, imageWidth, TRUE);

                /*
                  Final/open-ended column: never pad with trailing spaces.
                  Padding here can make an otherwise short row reach the
                  console edge and auto-wrap, after which OutLn() appears as
                  an extra blank line.
                */
                WCat(g_LineScratch,
                     sizeof(g_LineScratch) / sizeof(g_LineScratch[0]),
                     target);
            }

            OutLn(g_LineScratch);
            ++rowsOnPage;
        }
    }
}

static BOOL PromptYesNo(DWORD count)
{
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0, oldMode = 0, read = 0;
    INPUT_RECORD rec;
    WCHAR n[32];

    Out(L"\r\nClose all ");
    UIntToDec(count, n, sizeof(n) / sizeof(n[0]));
    Out(n);
    Out(L" matching handle(s)? <y/n> ");

    if (!GetConsoleMode(in, &oldMode)) {
        OutLn(L"\r\nInput is not a console, therefore cannot be terminated normally. Use f to force.");
        return FALSE;
    }

    mode = oldMode;
    mode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
    SetConsoleMode(in, mode);

    for (;;) {
        if (!ReadConsoleInputW(in, &rec, 1, &read)) {
            SetConsoleMode(in, oldMode);
            return FALSE;
        }

        if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown) {
            WCHAR ch = rec.Event.KeyEvent.uChar.UnicodeChar;
            if (ch == L'y' || ch == L'Y') {
                SetConsoleMode(in, oldMode);
                OutLn(L"y");
                return TRUE;
            }
            if (ch == L'n' || ch == L'N' ||
                rec.Event.KeyEvent.wVirtualKeyCode == VK_ESCAPE) {
                SetConsoleMode(in, oldMode);
                OutLn(L"n");
                return FALSE;
            }
        }
    }
}

static void TryEnableDebugPrivilege()
{
    HANDLE token = 0;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return;

    if (!LookupPrivilegeValueW(0, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return;
    }

    WhoMemSet(&tp, 0, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, 0, 0, 0);
    CloseHandle(token);
}



static WCHAR LowerAsciiW(WCHAR c)
{
    if (c >= L'A' && c <= L'Z') return c - L'A' + L'a';
    return c;
}

static BOOL WildMatchI(const WCHAR* pattern, const WCHAR* text)
{
    const WCHAR* star = 0;
    const WCHAR* starText = 0;

    if (!pattern || !text) return FALSE;

    while (*text) {
        if (*pattern == L'?' ||
            LowerAsciiW(*pattern) == LowerAsciiW(*text)) {
            ++pattern;
            ++text;
            continue;
        }

        if (*pattern == L'*') {
            star = pattern++;
            starText = text;
            continue;
        }

        if (star) {
            pattern = star + 1;
            text = ++starText;
            continue;
        }

        return FALSE;
    }

    while (*pattern == L'*') ++pattern;
    return *pattern == 0;
}

static BOOL HasWildcard(const WCHAR* s)
{
    SIZE_T i;
    if (!s) return FALSE;
    for (i = 0; s[i]; ++i)
        if (s[i] == L'*' || s[i] == L'?')
            return TRUE;
    return FALSE;
}

static BOOL EqualWordNoCase(const WCHAR* a, const WCHAR* b)
{
    return WEqualI(a, b);
}

static BOOL ProcessStemMatches(const WCHAR* actual, const WCHAR* wanted)
{
    WCHAR a[512], w[512];
    SIZE_T n;

    WCopy(a, sizeof(a) / sizeof(a[0]), actual);
    WCopy(w, sizeof(w) / sizeof(w[0]), wanted);

    n = WLen(a);
    if (n >= 4 &&
        LowerAsciiW(a[n-4]) == L'.' &&
        LowerAsciiW(a[n-3]) == L'e' &&
        LowerAsciiW(a[n-2]) == L'x' &&
        LowerAsciiW(a[n-1]) == L'e')
        a[n-4] = 0;

    n = WLen(w);
    if (n >= 4 &&
        LowerAsciiW(w[n-4]) == L'.' &&
        LowerAsciiW(w[n-3]) == L'e' &&
        LowerAsciiW(w[n-2]) == L'x' &&
        LowerAsciiW(w[n-1]) == L'e')
        w[n-4] = 0;

    return WildMatchI(w, a);
}

static BOOL ParseDwordValue(const WCHAR* s, DWORD* value)
{
    DWORD v = 0;
    DWORD base = 10;
    SIZE_T i = 0;

    if (!s || !*s || !value)
        return FALSE;

    if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) {
        base = 16;
        i = 2;
        if (!s[i])
            return FALSE;
    }

    for (; s[i]; ++i) {
        DWORD d;
        WCHAR c = s[i];

        if (c >= L'0' && c <= L'9')
            d = (DWORD)(c - L'0');
        else if (base == 16 && c >= L'a' && c <= L'f')
            d = 10 + (DWORD)(c - L'a');
        else if (base == 16 && c >= L'A' && c <= L'F')
            d = 10 + (DWORD)(c - L'A');
        else
            return FALSE;

        if (d >= base)
            return FALSE;

        if (v > (0xFFFFFFFFUL - d) / base)
            return FALSE;

        v = v * base + d;
    }

    *value = v;
    return TRUE;
}


static BOOL TerminatePid(DWORD pid)
{
    HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!p) return FALSE;
    {
        BOOL ok = TerminateProcess(p, 1);
        CloseHandle(p);
        return ok;
    }
}

static BOOL UserMatchesAnySelected(const WCHAR* user,
                                   const WHO_MATCH* selected,
                                   DWORD count)
{
    DWORD i;
    for (i = 0; i < count; ++i)
        if (WEqualI(user, selected[i].UserName))
            return TRUE;
    return FALSE;
}

static DWORD TerminateSelectedPids(const WHO_MATCH* selected,
                                   DWORD count,
                                   DWORD* failed)
{
    DWORD i, j, killed = 0;
    *failed = 0;

    for (i = 0; i < count; ++i) {
        BOOL already = FALSE;
        for (j = 0; j < i; ++j)
            if (selected[j].Pid == selected[i].Pid) {
                already = TRUE;
                break;
            }
        if (already) continue;

        if (TerminatePid(selected[i].Pid))
            ++killed;
        else
            ++(*failed);
    }
    return killed;
}

static DWORD TerminateSelectedUsers(const WHO_MATCH* selected,
                                    DWORD count,
                                    DWORD* failed)
{
    DWORD* pids;
    DWORD bytes = 0;
    DWORD capBytes = 64 * 1024;
    DWORD i, n, killed = 0;

    *failed = 0;
    if (!g_EnumProcesses)
        return 0;

    pids = (DWORD*)HeapAlloc(g_Heap, 0, capBytes);
    if (!pids)
        return 0;

    if (!g_EnumProcesses(pids, capBytes, &bytes)) {
        HeapFree(g_Heap, 0, pids);
        return 0;
    }

    n = bytes / sizeof(DWORD);

    for (i = 0; i < n; ++i) {
        HANDLE p;
        WCHAR user[256];

        if (!pids[i] || pids[i] == GetCurrentProcessId())
            continue;

        p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE,
                        FALSE, pids[i]);
        if (!p)
            continue;

        QueryProcessUser(p, user, sizeof(user) / sizeof(user[0]));
        CloseHandle(p);

        if (!UserMatchesAnySelected(user, selected, count))
            continue;

        if (TerminatePid(pids[i]))
            ++killed;
        else
            ++(*failed);
    }

    HeapFree(g_Heap, 0, pids);
    return killed;
}


static void PrintVersion()
{
#ifdef _WIN64
    const WCHAR* arch = L"x64";
#else
    const WCHAR* arch = L"x86";
#endif

    OutLn(L"WHO v1.0");
    Out(L"Architecture: ");
    OutLn(arch);
}

static int WhoMain(int argc, WCHAR** argv)
{
    const WCHAR* queryArg = 0;
    const WCHAR* effectiveQuery = 0;
    const WCHAR* processFilter = 0;
    BOOL actionClose = FALSE;
    BOOL actionTerminate = FALSE;
    BOOL actionUser = FALSE;
    BOOL force = FALSE;
    BOOL openScope = FALSE;
    BOOL usePid = FALSE, useHandle = FALSE;
    DWORD pidFilter = 0, handleFilter32 = 0;
    ULONG_PTR handleFilter = 0;

    WHO_MATCH* allMatches = 0;
    DWORD allCount = 0, allCap = 0;

    WCHAR** targets = 0;
    DWORD targetCount = 0;

    DWORD i, j;
    DWORD selected = 0;
    WHO_MATCH* selectedMatches = 0;

    if (argc < 2) {
        PrintUsage();
        return 2;
    }

    if (argc == 2 && WEqualI(argv[1], L"/?")) {
        PrintUsage();
        return 0;
    }

    if (argc == 2 && WEqualI(argv[1], L"/v")) {
        PrintVersion();
        return 0;
    }

    for (i = 1; i < (DWORD)argc; ++i) {
        if (IsOpt(argv[i], L'c')) {
            actionClose = TRUE;
        } else if (IsOpt(argv[i], L't')) {
            actionTerminate = TRUE;
        } else if (IsOpt(argv[i], L'u')) {
            actionUser = TRUE;
        } else if (IsOpt(argv[i], L'f')) {
            force = TRUE;
        } else if (EqualWordNoCase(argv[i], L"/a")) {
            openScope = TRUE;
        } else if (EqualWordNoCase(argv[i], L"/y")) {
            g_ShowImagePath = TRUE;
        } else if (EqualWordNoCase(argv[i], L"/z")) {
            g_ShowFullPath = TRUE;
        } else if (EqualWordNoCase(argv[i], L"/i")) {
            if (++i >= (DWORD)argc) { PrintUsage(); return 2; }
            processFilter = argv[i];
        } else if (EqualWordNoCase(argv[i], L"/d")) {
            if (++i >= (DWORD)argc || !ParseDwordValue(argv[i], &pidFilter)) {
                PrintUsage(); return 2;
            }
            usePid = TRUE;
        } else if (EqualWordNoCase(argv[i], L"/p")) {
            g_PauseOutput = TRUE;
        } else if (EqualWordNoCase(argv[i], L"/h")) {
            if (++i >= (DWORD)argc || !ParseDwordValue(argv[i], &handleFilter32)) {
                PrintUsage(); return 2;
            }
            handleFilter = (ULONG_PTR)handleFilter32;
            useHandle = TRUE;
        } else if (!queryArg) {
            queryArg = argv[i];
        } else {
            Err(L"Invalid arguments.\r\n");
            PrintUsage();
            return 2;
        }
    }

    {
        DWORD actions = (actionClose ? 1 : 0) +
                        (actionTerminate ? 1 : 0) +
                        (actionUser ? 1 : 0);

        if (actions > 1 || (force && actions == 0)) {
            PrintUsage();
            return 2;
        }

        if (!queryArg && !(processFilter || usePid || useHandle)) {
            PrintUsage();
            return 2;
        }
    }

#ifndef _WIN64
    if (RunningUnderWow64()) {
        Err(L"This is the 32-bit build running under WOW64.\r\n");
        Err(L"Use the native 64-bit build on x64 system.\r\n");
        return 3;
    }
#endif

    effectiveQuery = queryArg ? queryArg : L"*";

    TryEnableDebugPrivilege();
    OutLn(L"");

    /*
      Scope policy:

      Default (openScope == FALSE):
        enumerate matching filesystem objects in the current directory and
        inspect only handles to those exact objects.

      Open scope (/a):
        scan live File handles system-wide and match by their resolved names.

      This avoids the expensive all-handle name scan for commands such as
      "who /i chrome" unless the user explicitly requests open scope.
    */
    if (!openScope) {
        if (IsBroadPattern(effectiveQuery)) {
            WHO_MATCH* broadMatches = 0;
            DWORD broadCount = 0;
            DWORD cwdLen;

            cwdLen = GetCurrentDirectoryW(
                (DWORD)(sizeof(g_CurrentDirScratch) / sizeof(g_CurrentDirScratch[0])),
                g_CurrentDirScratch);

            if (!cwdLen ||
                cwdLen >= sizeof(g_CurrentDirScratch) / sizeof(g_CurrentDirScratch[0])) {
                Err(L"Unable to resolve current directory.\r\n");
                return 1;
            }

            TrimTrailingSlash(g_CurrentDirScratch);

            if (!FindMatches(effectiveQuery, FALSE,
                             processFilter, usePid, pidFilter,
                             useHandle, handleFilter,
                             TRUE,
                             &broadMatches, &broadCount)) {
                Err(L"Unable to enumerate open file names safely.\r\n");
                return 1;
            }

            for (i = 0; i < broadCount; ++i) {
                if (!PathIsInDirectoryI(broadMatches[i].Path,
                                        g_CurrentDirScratch))
                    continue;

                if (!AddUniqueMatch(&allMatches, &allCount, &allCap,
                                    &broadMatches[i])) {
                    HeapFree(g_Heap, 0, broadMatches);
                    if (allMatches) HeapFree(g_Heap, 0, allMatches);
                    Err(L"Out of memory.\r\n");
                    return 1;
                }
            }

            if (broadMatches)
                HeapFree(g_Heap, 0, broadMatches);
        } else {
            if (!ResolveCloseTargets(effectiveQuery, &targets, &targetCount)) {
                OutLn(L"No matching file/directory items found in current directory.");
                return 0;
            }

            for (i = 0; i < targetCount; ++i) {
            WHO_MATCH* one = 0;
            DWORD oneCount = 0;

            WCopy(g_ExactPath,
                  sizeof(g_ExactPath) / sizeof(g_ExactPath[0]),
                  targets[i]);

            g_TargetInfoValid = FALSE;
            {
                HANDLE target = CreateFileW(g_ExactPath, 0,
                                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                            0, OPEN_EXISTING,
                                            FILE_FLAG_BACKUP_SEMANTICS, 0);
                if (target != INVALID_HANDLE_VALUE) {
                    if (GetFileInformationByHandle(target, &g_TargetInfo))
                        g_TargetInfoValid = TRUE;
                    CloseHandle(target);
                }
            }

            if (!g_TargetInfoValid)
                continue;

            if (!FindMatches(g_ExactPath, TRUE,
                             processFilter, usePid, pidFilter,
                             useHandle, handleFilter,
                             FALSE,
                             &one, &oneCount)) {
                if (one) HeapFree(g_Heap, 0, one);
                FreePathArray(targets, targetCount);
                if (allMatches) HeapFree(g_Heap, 0, allMatches);
                Err(L"Unable to enumerate system handles.\r\n");
                return 1;
            }

            for (j = 0; j < oneCount; ++j) {
                if (!AddUniqueMatch(&allMatches, &allCount, &allCap, &one[j])) {
                    HeapFree(g_Heap, 0, one);
                    FreePathArray(targets, targetCount);
                    if (allMatches) HeapFree(g_Heap, 0, allMatches);
                    Err(L"Out of memory.\r\n");
                    return 1;
                }
            }

            if (one) HeapFree(g_Heap, 0, one);
            }

            FreePathArray(targets, targetCount);
            targets = 0;
            targetCount = 0;
        }
    } else {
        g_TargetInfoValid = FALSE;
        if (!FindMatches(effectiveQuery, FALSE,
                         processFilter, usePid, pidFilter,
                         useHandle, handleFilter,
                         IsBroadPattern(effectiveQuery),
                         &allMatches, &allCount)) {
            Err(L"Unable to enumerate open file names safely.\r\n");
            return 1;
        }
    }

    if (!allCount) {
        OutLn(L"No matching open handles found.");
        if (allMatches) HeapFree(g_Heap, 0, allMatches);
        return 0;
    }

    if (!(actionClose || actionTerminate || actionUser)) {
        DWORD visible = 0;
        WHO_MATCH* visibleMatches = 0;

        for (i = 0; i < allCount; ++i) {
            if (processFilter &&
                !ProcessStemMatches(allMatches[i].ProcessName, processFilter))
                continue;
            if (usePid && allMatches[i].Pid != pidFilter)
                continue;
            if (useHandle && allMatches[i].HandleValue != handleFilter)
                continue;
            ++visible;
        }

        if (!visible) {
            OutLn(L"No matching open handles found.");
            HeapFree(g_Heap, 0, allMatches);
            return 0;
        }

        visibleMatches = (WHO_MATCH*)HeapAlloc(
            g_Heap, 0, visible * sizeof(WHO_MATCH));
        if (!visibleMatches) {
            HeapFree(g_Heap, 0, allMatches);
            Err(L"Out of memory.\r\n");
            return 1;
        }

        {
            DWORD s = 0;
            for (i = 0; i < allCount; ++i) {
                if (processFilter &&
                    !ProcessStemMatches(allMatches[i].ProcessName, processFilter))
                    continue;
                if (usePid && allMatches[i].Pid != pidFilter)
                    continue;
                if (useHandle && allMatches[i].HandleValue != handleFilter)
                    continue;
                WhoMemCopy(&visibleMatches[s], &allMatches[i], sizeof(WHO_MATCH));
                ++s;
            }
        }

        PrintMatches(visibleMatches, visible);
        HeapFree(g_Heap, 0, visibleMatches);
        HeapFree(g_Heap, 0, allMatches);
        return 0;
    }

    for (i = 0; i < allCount; ++i) {
        if (processFilter &&
            !ProcessStemMatches(allMatches[i].ProcessName, processFilter))
            continue;
        if (usePid && allMatches[i].Pid != pidFilter)
            continue;
        if (useHandle && allMatches[i].HandleValue != handleFilter)
            continue;
        ++selected;
    }

    if (!selected) {
        OutLn(L"No matching handles remain after applying the filter(s).");
        HeapFree(g_Heap, 0, allMatches);
        return 1;
    }

    selectedMatches = (WHO_MATCH*)HeapAlloc(
        g_Heap, 0, selected * sizeof(WHO_MATCH));
    if (!selectedMatches) {
        HeapFree(g_Heap, 0, allMatches);
        Err(L"Out of memory.\r\n");
        return 1;
    }

    {
        DWORD s = 0;
        for (i = 0; i < allCount; ++i) {
            if (processFilter &&
                !ProcessStemMatches(allMatches[i].ProcessName, processFilter))
                continue;
            if (usePid && allMatches[i].Pid != pidFilter)
                continue;
            if (useHandle && allMatches[i].HandleValue != handleFilter)
                continue;

            WhoMemCopy(&selectedMatches[s], &allMatches[i], sizeof(WHO_MATCH));
            ++s;
        }
    }

    if (actionClose)
        OutLn(L"Handles selected for closing:");
    else if (actionTerminate)
        OutLn(L"Handles whose owning process(es) will be terminated:");
    else
        OutLn(L"Handles whose owning user account(s) will be terminated:");

    PrintMatches(selectedMatches, selected);
    OutLn(L"");

    if (actionClose) {
        OutLn(L"WARNING: forcibly closing another process's handle can cause");
        OutLn(L"data loss or data corruption.");
    } else if (actionTerminate) {
        OutLn(L"WARNING: this will terminate the owning process(es).");
    } else {
        OutLn(L"WARNING: this will terminate ALL processes belonging to each");
        OutLn(L"user account represented in the selected handle list.");
    }

    if (!force && !PromptYesNo(selected)) {
        OutLn(L"Cancelled.");
        HeapFree(g_Heap, 0, selectedMatches);
        HeapFree(g_Heap, 0, allMatches);
        return 1;
    }

    if (actionClose) {
        DWORD closed = 0, failed = 0;

        for (i = 0; i < selected; ++i) {
            WCHAR pid[32], hv[32];

            if (CloseVerifiedHandle(&selectedMatches[i],
                                    selectedMatches[i].Path)) {
                ++closed;
                Out(L"closed  PID ");
            } else {
                ++failed;
                Out(L"FAILED  PID ");
            }

            UIntToDec(selectedMatches[i].Pid, pid,
                      sizeof(pid) / sizeof(pid[0]));
            UIntPtrToHex(selectedMatches[i].HandleValue, hv,
                         sizeof(hv) / sizeof(hv[0]));
            Out(pid);
            Out(L"  handle ");
            Out(hv);
            Out(L"  ");
            OutLn(selectedMatches[i].Path);
        }

        {
            WCHAR a[32], b[32];
            UIntToDec(closed, a, sizeof(a) / sizeof(a[0]));
            UIntToDec(failed, b, sizeof(b) / sizeof(b[0]));
            Out(L"\r\nClosed: "); Out(a);
            Out(L", failed: "); OutLn(b);
        }

        HeapFree(g_Heap, 0, selectedMatches);
        HeapFree(g_Heap, 0, allMatches);
        return failed ? 1 : 0;
    }

    if (actionTerminate) {
        DWORD failed = 0;
        DWORD killed = TerminateSelectedPids(selectedMatches, selected, &failed);
        WCHAR a[32], b[32];
        UIntToDec(killed, a, sizeof(a) / sizeof(a[0]));
        UIntToDec(failed, b, sizeof(b) / sizeof(b[0]));
        Out(L"Processes terminated: "); Out(a);
        Out(L", failed: "); OutLn(b);

        HeapFree(g_Heap, 0, selectedMatches);
        HeapFree(g_Heap, 0, allMatches);
        return failed ? 1 : 0;
    }

    {
        DWORD failed = 0;
        DWORD killed = TerminateSelectedUsers(selectedMatches, selected, &failed);
        WCHAR a[32], b[32];
        UIntToDec(killed, a, sizeof(a) / sizeof(a[0]));
        UIntToDec(failed, b, sizeof(b) / sizeof(b[0]));
        Out(L"User processes terminated: "); Out(a);
        Out(L", failed: "); OutLn(b);

        HeapFree(g_Heap, 0, selectedMatches);
        HeapFree(g_Heap, 0, allMatches);
        return failed ? 1 : 0;
    }
}

// Custom CRT-free entry point.
extern "C" void mainCRTStartup(void)
{
    WCHAR** argv = 0;
    WCHAR* storage = 0;
    int argc;
    int rc = 1;

    g_Heap = GetProcessHeap();
    if (!g_Heap) ExitProcess(1);

    argc = ParseCommandLine(&argv, &storage);

    if (!LoadApis()) {
        Err(L"Required NT native APIs are unavailable.\r\n");
        rc = 1;
    } else {
        rc = WhoMain(argc, argv);
    }

    if (argv) HeapFree(g_Heap, 0, argv);
    if (storage) HeapFree(g_Heap, 0, storage);
    ExitProcess((UINT)rc);
}
