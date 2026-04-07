#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <TlHelp32.h>
#include <iostream>

bool IsMemoryReadable(void* p, SIZE_T size)
{
    if (p == nullptr)
        return false;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0)
        return false;

    if (!(mbi.State & MEM_COMMIT) || !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
        return false;

    ULONG64 endAddr = (ULONG64)mbi.BaseAddress + mbi.RegionSize;
    if ((ULONG64)p + size > endAddr)
        return false;

    return true;
}

// 获取当前进程所有线程的 TID
std::vector<DWORD> GetProcessThreadIds()
{
    std::vector<DWORD> tids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return tids;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    DWORD currentPid = GetCurrentProcessId();

    if (Thread32First(hSnapshot, &te32))
    {
        do
        {
            if (te32.th32OwnerProcessID == currentPid)
            {
                tids.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return tids;
}

// 暴力扫描当前进程所有 TEB
void ScanTEB_CurrentProcess()
{
    const ULONG64 TEB_START = 0x000000000000;
    const ULONG64 TEB_END = 0x7FF000000000;
    const ULONG64 STEP = 0x1000;

    DWORD currentPid = GetCurrentProcessId();
    std::vector<DWORD> threadIds = GetProcessThreadIds();

    printf("当前进程 PID: %d, 线程数: %zu\n", currentPid, threadIds.size());
    printf("开始扫描地址范围: %p - %p\n\n", (void*)TEB_START, (void*)TEB_END);

    int foundCount = 0;

    for (ULONG64 addr = TEB_START; addr < TEB_END; addr += STEP)
    {
        if (!IsMemoryReadable((void*)addr, 0x100))
            continue;

        DWORD pid = *(DWORD*)(addr + 0x40);
        DWORD tid = *(DWORD*)(addr + 0x48);

        if (pid != currentPid)
            continue;

        bool isValidTid = false;
        for (DWORD validTid : threadIds)
        {
            if (tid == validTid)
            {
                isValidTid = true;
                break;
            }
        }

        if (!isValidTid)
            continue;

        foundCount++;
        printf("[%d] TEB: %p | PID: %d | TID: %d\n", foundCount, (void*)addr, pid, tid);
    }

    printf("\n扫描完成，找到 %d 个 TEB\n", foundCount);
}

int main()
{
    printf("===== 暴力扫描当前进程所有 TEB =====\n\n");
    ScanTEB_CurrentProcess();
    printf("\n===== 完成 =====\n");
    system("pause");
    return 0;
}
