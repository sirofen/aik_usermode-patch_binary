#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <shlwapi.h>

#include <string>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shlwapi.lib")

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
            std::printf("Pattern address found: 0x%llX\n", rel_pattern_addr += (std::uint64_t) mbi.BaseAddress);
            delete[] buf;
            CloseHandle(process);
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

    printf("%lu bytes written\n", bytes_written);

    CloseHandle(hfile);
    return true;
}

std::uint64_t dynamic_module_search(char* bin, char* module_req, std::uint64_t pattern) {
    std::string_view pattern_sv(reinterpret_cast<char*>(&pattern), sizeof(pattern));
    // start process
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    HMODULE hmods[1024];
    DWORD bytes_required;
    char module_name[MAX_PATH];
    MODULEINFO module_info;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL,
                        bin,
                        NULL,
                        NULL,
                        FALSE,
                        CREATE_NO_WINDOW,
                        NULL,
                        NULL,
                        &si,
                        &pi)
            ) {
        std::printf("CreateProcess err: 0x%lX\n", GetLastError());
        return 0;
    }

    // Wait for process to load
    WaitForInputIdle(pi.hProcess, INFINITE);

    // it may take some time for process to load
    Sleep(1000);
    if(!EnumProcessModules(pi.hProcess, hmods, sizeof(hmods), &bytes_required)) {
        std::printf("EnumProcessModules err: 0x%lX\n", GetLastError());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }

    for (std::uint64_t i = 0; i < (bytes_required / sizeof(HMODULE)); i++) {
        ZeroMemory(module_name, sizeof(module_name));

        if (!GetModuleFileNameEx(pi.hProcess,
                                 hmods[i],
                                 module_name,
                                 sizeof(module_name))) {
            std::printf("GetModuleFileNameEx err: 0x%lX\n", GetLastError());
            continue;
        }

        if (StrStrIA(module_name, module_req) == NULL) {
            continue;
        }

        if (!GetModuleInformation(pi.hProcess,
                                 hmods[i],
                                 &module_info,
                                 sizeof(module_info))) {
            std::printf("GetModuleInformation err: 0x%lX\n", GetLastError());
            continue;
        }

        std::uint64_t module_end_addr = (std::uint64_t) module_info.lpBaseOfDll + module_info.SizeOfImage;
        MEMORY_BASIC_INFORMATION mbi;

        for (auto addr = (std::uint64_t) module_info.lpBaseOfDll;
             VirtualQueryEx(pi.hProcess, (PVOID) addr, &mbi, sizeof(mbi)) != 0 && addr < module_end_addr;
             addr += mbi.RegionSize) {
            if (!addr || mbi.State != MEM_COMMIT || mbi.Protect & PAGE_NOACCESS || mbi.Protect & PAGE_GUARD) {
                continue;
            }

            char* buf = new char[mbi.RegionSize];
            if (!ReadProcessMemory(pi.hProcess, mbi.BaseAddress, buf, mbi.RegionSize, NULL)) {
                std::printf("ReadProcessMemory err: 0x%lX\n", GetLastError());
                delete[] buf;
                continue;
            }

            std::string_view sv(buf, mbi.RegionSize);

            if (std::uint64_t rel_pattern_addr = sv.find(pattern_sv); rel_pattern_addr != sv.npos) {
                std::printf("Pattern address found: 0x%llX\n", rel_pattern_addr += (std::uint64_t) mbi.BaseAddress - (std::uint64_t) module_info.lpBaseOfDll);
                delete[] buf;
                TerminateProcess(pi.hProcess, 0);

                WaitForSingleObject(pi.hProcess, INFINITE);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return rel_pattern_addr;
            }
            delete[] buf;
        }
    }
    TerminateProcess(pi.hProcess, 0);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

std::uint64_t dynamic_search(char* bin, std::uint64_t pattern_i) {
    // start process
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL,
                        bin,
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
        return 0;
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
    return pattern_offset;
}

std::uint64_t static_search(char* file, std::uint64_t pattern_i) {
    HANDLE hfile;
    LONGLONG file_size = 0;

    hfile = CreateFileA(file,
                        GENERIC_READ,
                        0,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);

    if (hfile == INVALID_HANDLE_VALUE) {
        std::printf("CreateFile err: 0x%lX\n", GetLastError());
        CloseHandle(hfile);
        return 0;
    }


    if (!GetFileSizeEx(hfile, (LARGE_INTEGER*)&file_size)) {
        std::printf("GetFileSizeEx err: 0x%lX\n", GetLastError());
        return 0;
    }

    char* file_buf = new char[file_size];

    if (!ReadFile(hfile,
                  file_buf,
                  file_size,
                  NULL,
                  NULL)) {
        std::printf("ReadFile err: 0x%lX\n", GetLastError());
        delete[] file_buf;
        CloseHandle(hfile);
        return 0;
    }

    std::string_view sv(file_buf, file_size);
    std::string_view pattern_sv(reinterpret_cast<char*>(&pattern_i), sizeof(pattern_i));

    if (std::uint64_t rel_pattern_addr = sv.find(pattern_sv); rel_pattern_addr != sv.npos) {
        std::printf("Pattern address found: 0x%llX\n", rel_pattern_addr);
        delete[] file_buf;
        CloseHandle(hfile);
        return rel_pattern_addr;
    }

    delete[] file_buf;
    CloseHandle(hfile);
    return 0;
}

int main(int argc, char* argv[]) {
    // app path
    // pattern
    // opt static search
    // opt module name search
    // opt program args
    if (argc < 3) {
        std::printf("invalid arguments");
        return 1;
    }

    std::uint64_t pattern_i = _strtoui64(argv[2], NULL, 16);

    std::uint64_t pattern_offset;

    char proc_cmd[MAX_PATH]{};

    std::memcpy(proc_cmd, argv[1], std::strlen(argv[1]));
    if (argv[5]) {
        proc_cmd[std::strlen(argv[1])] = ' ';
        std::memcpy(&proc_cmd[std::strlen(argv[1]) + 1], argv[5], std::strlen(argv[5]));
    }

    if (!argv[3]) {
        std::printf("Dynamic search...\n");
        pattern_offset = dynamic_search(proc_cmd, pattern_i);
    } else if (!argv[4]) {
        std::printf("Static search...\n");
        pattern_offset = static_search(proc_cmd, pattern_i);
    } else {
        std::printf("Module search...\n");
        pattern_offset = dynamic_module_search(proc_cmd, argv[4], pattern_i);
    }

    static_assert(sizeof(pattern_offset) == kPayloadSize);

    if (!pattern_offset) {
        std::printf("Pattern not found");
        return 1;
    }

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