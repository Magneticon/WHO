// patchsubsys.cpp
// Build-tool helper for experimentation with NT 4.
// This program runs on the XP build machine and changes the PE
// MajorSubsystemVersion/MinorSubsystemVersion fields of an EXE.
//
// Usage:
//   cl /nologo /EHsc patchsubsys.cpp
//   patchsubsys Release\who.exe 4 0
//
// IMPORTANT: changing the PE header does not make newer imports compatible.
// Always inspect "dumpbin /imports who.exe" before trying the binary on NT 4.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int wmain(int argc, wchar_t** argv)
{
    HANDLE h;
    IMAGE_DOS_HEADER dos;
    DWORD got;
    DWORD sig;
    WORD magic;
    LONG pe;
    WORD majorv, minorv;

    if (argc != 4) {
        fwprintf(stderr, L"usage: patchsubsys <exe> <major> <minor>\n");
        return 2;
    }

    majorv = (WORD)_wtoi(argv[2]);
    minorv = (WORD)_wtoi(argv[3]);

    h = CreateFileW(argv[1], GENERIC_READ | GENERIC_WRITE, 0, 0,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (h == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"cannot open %s (error %lu)\n", argv[1], GetLastError());
        return 1;
    }

    if (!ReadFile(h, &dos, sizeof(dos), &got, 0) || got != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fwprintf(stderr, L"not a valid DOS/PE image\n");
        CloseHandle(h);
        return 1;
    }

    pe = dos.e_lfanew;
    SetFilePointer(h, pe, 0, FILE_BEGIN);
    if (!ReadFile(h, &sig, sizeof(sig), &got, 0) || got != sizeof(sig) ||
        sig != IMAGE_NT_SIGNATURE) {
        fwprintf(stderr, L"not a valid PE image\n");
        CloseHandle(h);
        return 1;
    }

    // COFF header follows signature; OptionalHeader follows COFF header.
    SetFilePointer(h, sizeof(IMAGE_FILE_HEADER), 0, FILE_CURRENT);
    if (!ReadFile(h, &magic, sizeof(magic), &got, 0) || got != sizeof(magic)) {
        CloseHandle(h);
        return 1;
    }

    // MajorSubsystemVersion is at offset 48 from the start of both
    // IMAGE_OPTIONAL_HEADER32 and IMAGE_OPTIONAL_HEADER64.
    SetFilePointer(h, pe + 4 + sizeof(IMAGE_FILE_HEADER) + 48, 0, FILE_BEGIN);
    if (!WriteFile(h, &majorv, sizeof(majorv), &got, 0) || got != sizeof(majorv) ||
        !WriteFile(h, &minorv, sizeof(minorv), &got, 0) || got != sizeof(minorv)) {
        fwprintf(stderr, L"write failed (error %lu)\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    CloseHandle(h);
    wprintf(L"patched %s subsystem version to %u.%u\n", argv[1], majorv, minorv);
    return 0;
}
