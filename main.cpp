#include <windows.h>
#include <winternl.h>

#include <string>

#pragma comment(lib, "ntdll.lib")

namespace {
    constexpr auto kBinStubMsgOffset = 0x4E;
    constexpr auto kPayloadOffset = 0x20;
    constexpr auto kPayloadSize = 8;
    constexpr char kMsg[] = "Surely it's just a DOS stub msg" /* \0 */;
}

std::uint64_t process_find_pattern(DWORD pid, std::uint64_t pattern) {
    std::string_view pattern_sv(reinterpret_cast<char*>(&pattern), sizeof(pattern));

    HANDLE process = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            false,
            pid);

    if (!process) {
        std::printf("OpenProcess err: 0x%lX", GetLastError());
        return 1;
    }

    MEMORY_BASIC_INFORMATION mbi;

    for (std::uint64_t addr = 0;
         VirtualQueryEx(process, (PVOID) addr, &mbi, sizeof(mbi)) != 0;
         addr += mbi.RegionSize) {
        if (!addr || mbi.State != MEM_COMMIT || mbi.Protect & PAGE_NOACCESS || mbi.Protect & PAGE_GUARD) {
            continue;
        }

        char* buf = new char[mbi.RegionSize];
        if (!ReadProcessMemory(process, mbi.BaseAddress, buf, mbi.RegionSize, NULL)) {
            delete[] buf;
            CloseHandle(process);
            return false;
        }

        std::string_view sv(buf, mbi.RegionSize);

        if (std::uint64_t rel_pattern_addr = sv.find(pattern_sv); rel_pattern_addr != sv.npos) {
            delete[] buf;
            CloseHandle(process);
            std::printf("pattern address found: 0x%llX\n", rel_pattern_addr += (std::uint64_t) mbi.BaseAddress);
            return rel_pattern_addr;
        }
        delete[] buf;
    }

    CloseHandle(process);
    return 0;
}

std::uint64_t process_base_image(HANDLE process) {
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;
    ZeroMemory(&pbi, sizeof(pbi));

    status = NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

    if (!NT_SUCCESS(status)) {
        return 0;
    }

    std::uint64_t image_base;
    if (!ReadProcessMemory(process, &pbi.PebBaseAddress->Reserved3[1], &image_base, sizeof(image_base), NULL)) {
        return 0;
    }
    return image_base;
}

bool write_to_file(const char* path, std::uint64_t pos, std::string_view bytes) {
    HANDLE hfile;
    OVERLAPPED ovr{};
    DWORD bytes_written = 0;

    hfile = CreateFileA(path,
                        GENERIC_WRITE,
                        0,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);

    if (hfile == INVALID_HANDLE_VALUE) {
        std::printf("CreateFile err: 0x%lX\n", GetLastError());
        CloseHandle(hfile);
        return false;
    }

    ovr.OffsetHigh = 0;
    ovr.Offset = pos;

    if (!WriteFile(hfile,
                   bytes.data(),
                   bytes.size(),
                   &bytes_written,
                   &ovr)) {
        printf("WriteFile err: 0x%lX", GetLastError());
        CloseHandle(hfile);
        return false;
    }

    if (bytes_written != bytes.size()) {
        printf("Error: dwBytesWritten != dwBytesToWrite\n");
        CloseHandle(hfile);
        return false;
    }

    printf("Wrote %lu bytes\n", bytes_written);

    CloseHandle(hfile);
    return true;
}

int main(int argc, char* argv[]) {
    // app path
    // pattern
    if (argc < 3) {
        std::printf("invalid arguments");
        return 1;
    }

    std::uint64_t pattern_i = _strtoui64(argv[2], NULL, 16);

    // start process
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL,
                        argv[1],
                        NULL,
                        NULL,
                        FALSE,
                        CREATE_SUSPENDED,
                        NULL,
                        NULL,
                        &si,
                        &pi)
            ) {
        std::printf("CreateProcess err: 0x%lX\n", GetLastError());
        return 1;
    }

    // find key pattern
    std::uint64_t pattern_addr = process_find_pattern(pi.dwProcessId, pattern_i);
    std::uint64_t image_base = process_base_image(pi.hProcess);

    TerminateProcess(pi.hProcess, 0);

    WaitForSingleObject(pi.hProcess, INFINITE);

    if (!pattern_addr || !image_base) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // on assumption that pattern variable is in the static memory, this should be constant image base offset
    std::uint64_t pattern_offset = pattern_addr - image_base;
    std::printf("Pattern offset: 0x%llX\n", pattern_offset);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    static_assert(sizeof(pattern_offset) == kPayloadSize);

    char buf[40];
    if (memcpy_s(buf, sizeof(buf), kMsg, sizeof(kMsg)) ||
        memcpy_s(&buf[kPayloadOffset], kPayloadSize, &pattern_offset, sizeof(pattern_offset))) {
        std::printf("memcpy_s err");
        return 1;
    }

    // modify binary
    if (!write_to_file(argv[1], kBinStubMsgOffset, std::string_view(buf, sizeof(buf)))) {
        return 1;
    }

    return 0;
}