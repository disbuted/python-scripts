import os
import shutil
import ctypes
from tqdm import tqdm

def admin():
    """Check if the script is running with administrator privileges."""
    return ctypes.windll.shell32.IsUserAnAdmin() != 0

def files(folder_path, folder_name):
    """Delete all files in a folder and show a progress bar."""
    if not os.path.exists(folder_path):
        print(f"{folder_name} does not exist.")
        return
    
    files = os.listdir(folder_path)
    if not files:
        print(f"{folder_name} is already empty.")
        return
    
    print(f"Clearing {folder_name}...")
    with tqdm(total=len(files), desc=f"{folder_name} Progress", unit="file") as pbar:
        for file in files:
            file_path = os.path.join(folder_path, file)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception:
                pass
            pbar.update(1)

if __name__ == "__main__":
    if not admin():
        print("This script must be run as an administrator to clear the Prefetch folder.")
    
    temp = os.path.join(os.getenv('SystemRoot'), 'Temp')
    user_temp = os.path.join(os.getenv('TEMP'))
    prefetch = os.path.join(os.getenv('SystemRoot'), 'Prefetch')
    
    files(temp, "System Temp Folder")
    files(user_temp, "User Temp Folder")
    
    if admin():
        files(prefetch, "Prefetch Folder")
    
    input("Press Enter to exit...")
