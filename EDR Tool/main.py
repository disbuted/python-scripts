import os
import subprocess
import sys
import time
import ctypes
import colorama
import pystyle
import logging
from colorama import Fore, init, Style
from os import system
    
yellow_dash = f"{Fore.YELLOW}-{Style.RESET_ALL}"
red_dash = f"{Fore.RED}-{Style.RESET_ALL}"
green_dash = f"{Fore.GREEN}-{Style.RESET_ALL}"
blue_dash = f"{Fore.BLUE}-{Style.RESET_ALL}"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def clear_file_logs():
    if not is_admin():
        print(f"\r[{red_dash}] This script requires administrative privileges to run.")
        print(f"\r[{red_dash}] Please run the script as an administrator.")
        return

    log_categories = [
        "Security",  
        "System", 
        "Microsoft-Windows-Security-Auditing",
        "Microsoft-Windows-FileHistory-Engine",
        "Microsoft-Windows-NTFS",
        "Microsoft-Windows-PowerShell/Operational"
    ]
    
    result = subprocess.run(["wevtutil", "el"], capture_output=True, text=True)
    available_logs = result.stdout.splitlines()
    
    cleared_count = 0
    
    for log in log_categories:
        if log in available_logs:
            try:
                subprocess.run(["wevtutil", "cl", log], check=True)
                cleared_count += 1
            except subprocess.CalledProcessError as e:
                print(f"\r[{red_dash}] Failed to clear log {log}: {e}")
        else:
            print(f"\r[{yellow_dash}] Log {log} does not exist.")
    
    print(f"\r[{green_dash}] Total logs cleared: {cleared_count}")

def wipe_log_files():
    log_dirs = [
        r"C:\Windows\System32\winevt\Logs", 
        r"C:\Windows\Logs", 
        r"C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\IE"  
    ]
    
    deleted_count = 0
    
    for log_dir in log_dirs:
        # Expand any wildcards in the directory path
        expanded_dirs = [os.path.expandvars(log_dir)]
        
        for expanded_dir in expanded_dirs:
            if os.path.exists(expanded_dir):
                for root, dirs, files in os.walk(expanded_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            os.remove(file_path)
                            deleted_count += 1
                        except Exception:
                            pass
    
    print(f"\r[{green_dash}] Total log files deleted: {deleted_count}")

def disable_logging_services():
    services = ["Wecsvc", "EventLog"]
    
    for service in services:
        subprocess.run(["sc", "stop", service], shell=True)
        subprocess.run(["sc", "config", service, "start= disabled"], shell=True)
        print(f"\r[{green_dash}] Disabled {service}")

def disable_etw():
    ntdll = ctypes.windll.LoadLibrary("ntdll.dll")
    etw_event_write = ctypes.windll.ntdll.EtwEventWrite
    patch = (ctypes.c_char * 1)(b"\xC3") 
    ctypes.windll.kernel32.VirtualProtect(etw_event_write, 1, 0x40, ctypes.byref(ctypes.c_ulong()))
    ctypes.memmove(etw_event_write, patch, 1)
    print(f"\r[{green_dash}] ETW Logging Disabled")

def secure_wipe(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r+b") as file:
            file.seek(0)
            file.write(os.urandom(os.path.getsize(file_path)))  
        os.remove(file_path)
        print(f"\r[{green_dash}] Securely wiped & deleted {file_path}")

def take_ownership(file_path):
    subprocess.run(f'takeown /f "{file_path}"', shell=True)
    subprocess.run(f'icacls "{file_path}" /grant %USERNAME%:F', shell=True)
    print(f"\r[{green_dash}] Windows logs cleared using LOLBins")
    
    
def secure_wipe(file_path):
    if os.path.exists(file_path):
        try:
            with open(file_path, "r+b") as file:
                file.seek(0)
                file.write(os.urandom(os.path.getsize(file_path))) 
            os.remove(file_path)
            print(f"\r[{green_dash}] Securely wiped and deleted {file_path}")
        except Exception as e:
            print(f"\r[{red_dash}] Failed to wipe {file_path}: {e}")
    else:
        print(f"\r[{red_dash}] File not found: {file_path}")

def wipe_disk():
    subprocess.run("cipher /w:C:", shell=True)
    print(f"\r[{green_dash}] Disk free space wiped")

def inject_into_process(target_process):
    CREATE_SUSPENDED = 0x00000004
    try:
        process = subprocess.Popen(target_process, creationflags=CREATE_SUSPENDED)
        time.sleep(2)
        kernel32 = ctypes.windll.kernel32
        kernel32.ResumeThread(process._handle)
        print(f"\r[{green_dash}] Successfully injected into {target_process}")
    
    except Exception as e:
        print(f"\r[{red_dash}] Error: {e}")
        
        
def rem_vun_driver_reg():
    key_path = r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Config'
    value_name = "VulnerableDriverBlocklistEnable"

    query_cmd = f'reg query "{key_path}" /v {value_name}'
    query_result = subprocess.run(query_cmd, shell=True, capture_output=True, text=True)
    
    if query_result.returncode != 0:
        print(f"\r[{yellow_dash}] The registry value '{value_name}' does not exist in '{key_path}'.")
    else:
        print(f"\r[{yellow_dash}] The registry value '{value_name}' exists. Attempting to delete it...")
        delete_cmd = f'reg delete "{key_path}" /v {value_name} /f'
        delete_result = subprocess.run(delete_cmd, shell=True, capture_output=True, text=True)
        
        if delete_result.returncode == 0:
            print(f"\r[{green_dash}] Successfully deleted '{value_name}' from '{key_path}'.")
        else:
            print(f"\r[{red_dash}] Failed to delete '{value_name}' from '{key_path}'.")
            print("Error:", delete_result.stderr)

def main():
        os.system('title Screenshare Tool By @humbleness')
        os.system("mode con: cols=158 lines=30")
        inject_into_process()
      # print(f"\r[{green_dash}] Injected into explorer.exe")
      # rem_vun_driver_reg()
      # disable_etw()  
        time.sleep(1)                                                         
      # wipe_disk() # not rlly needed but a good addition :D
      # clear_file_logs() 
      # disable_logging_services()  # need to fix this 
      # wipe_log_files() # needs admin perms to do :D
        print(f"\r[{green_dash}] Bypass' Applied!")
        print(f"\r[{green_dash}] Good luck with your ss!")
        os.system("pause")

#if __name__ == "__main__":
#    main()

if __name__ == "__main__":
    if not is_admin():
        print(f"\r[{red_dash}] Relaunching with Administrator privileges...")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, __file__, None, 1
        )
        sys.exit()
    else:
        print(f"\r[{green_dash}] Running with Administrator privileges!")
        main()
