# TEB Brute-Force Scanner

A Windows tool that performs a brute-force memory scan to locate Thread Environment Blocks (TEBs) within the current process.

## Overview

This program scans a wide range of virtual memory addresses (`0x000000000000` to `0x7FF000000000`) in 4KB increments to identify valid TEB structures belonging to the current process. It validates potential TEBs by checking:

- Memory readability
- Process ID (PID) matches the current process
- Thread ID (TID) matches an active thread in the process

## How It Works

1. **Get Thread List** – Retrieves all active thread IDs belonging to the current process using `CreateToolhelp32Snapshot`
2. **Brute-Force Scan** – Iterates through memory addresses from `0` to `0x7FF000000000` in `0x1000` (4KB) steps
3. **Memory Validation** – Uses `VirtualQuery` to check if each address points to a readable, committed memory region
4. **TEB Structure Validation** – Reads potential PID and TID offsets (`+0x40` and `+0x48` respectively) from each candidate address
5. **Verification** – Confirms that the PID matches the current process and the TID exists in the thread list

## TEB Offsets

The offsets used in this scanner are specific to Windows x64:

| Offset | Field          | Description           |
|--------|----------------|-----------------------|
| `+0x40`| `ClientId.UniqueProcess` | Process ID (PID) |
| `+0x48`| `ClientId.UniqueThread`  | Thread ID (TID) |

## Requirements

- Windows operating system (x64)
- Visual Studio or any C++ compiler with Windows SDK
- Windows SDK (for `Windows.h`, `TlHelp32.h`)

## Compilation

### Using Visual Studio (Developer Command Prompt)

```bash
cl /EHsc TEB_Scanner.cpp
```

### Using MinGW/GCC

```bash
g++ TEB_Scanner.cpp -o TEB_Scanner.exe -luser32 -lkernel32
```

## Usage

Simply run the compiled executable:

```bash
TEB_Scanner.exe
```

### Sample Output

```
===== Brute-Force Scan for TEBs in Current Process =====

Current Process PID: 12345, Thread Count: 4
Scanning address range: 0x0 - 0x7FF000000000

[1] TEB: 0x7FF6A1B40000 | PID: 12345 | TID: 12348
[2] TEB: 0x7FF6A1B41000 | PID: 12345 | TID: 12352
[3] TEB: 0x7FF6A1B42000 | PID: 12345 | TID: 12360
[4] TEB: 0x7FF6A1B43000 | PID: 12345 | TID: 12368

Scan complete, found 4 TEB(s)

===== Done =====
```

## Limitations

- **Performance** – Scanning from `0` to `0x7FF000000000` in 4KB steps requires approximately **8.3 million iterations** (0x7FF000000000 / 0x1000 ≈ 8.3 × 10⁶ checks)
- **Windows Version Dependency** – TEB offsets (`+0x40`, `+0x48`) may vary between Windows versions (tested on Windows 10/11 x64)
- **No SEH Handling** – Direct memory access without structured exception handling could crash on invalid addresses (mitigated by `IsMemoryReadable` pre-check)

## Possible Improvements

- Add exception handling (`__try/__except`) for additional safety
- Make offsets configurable or auto-detect based on Windows version
- Use `NtQuerySystemInformation` for more efficient TEB enumeration
- Add multi-threaded scanning for better performance
- Limit scan range to user-mode addresses only

## Legal & Ethical Disclaimer

This tool is intended for **educational purposes only**. Understanding TEB layout and memory scanning techniques is valuable for debugging, reverse engineering, and security research. Unauthorized use against software you do not own or have explicit permission to analyze may violate laws and software licenses.

## License

MIT License – Free for educational and research use.
