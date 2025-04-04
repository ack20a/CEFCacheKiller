import os
import string
import shutil
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cache_cleaner.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
def get_available_drives():
    drives = []
    for drive in string.ascii_uppercase:
        if os.path.exists(f"{drive}:"):
            drives.append(f"{drive}:")
    return drives
def scan_for_user_data(drive):
    user_data_folders = []
    logging.info(f"开始扫描磁盘 {drive}")
    try:
        for root, dirs, _ in os.walk(drive, topdown=True):
            dirs[:] = [d for d in dirs if d not in ["Windows", "$Recycle.Bin", "System Volume Information"]]
            if "User Data" in dirs:
                user_data_path = os.path.join(root, "User Data")
                user_data_folders.append(user_data_path)
                logging.info(f"找到User Data文件夹: {user_data_path}")
    except Exception as e:
        logging.error(f"扫描{drive}时出错: {str(e)}")
    return user_data_folders
def delete_cache_in_user_data(user_data_path):
    deleted_count = 0
    total_size = 0
    try:
        for root, dirs, _ in os.walk(user_data_path):
            for dir_name in dirs:
                if "cache" in dir_name.lower():
                    cache_path = os.path.join(root, dir_name)
                    try:
                        folder_size = sum(f.stat().st_size for f in Path(cache_path).glob('**/*') if f.is_file())
                        total_size += folder_size
                        shutil.rmtree(cache_path)
                        deleted_count += 1
                        logging.info(f"已删除: {cache_path} (大小: {folder_size/1024/1024:.2f} MB)")
                    except Exception as e:
                        logging.error(f"删除{cache_path}时出错: {str(e)}")
    except Exception as e:
        logging.error(f"处理{user_data_path}时出错: {str(e)}")
    return deleted_count, total_size
def main():
    logging.info("Cache清理工具启动")
    drives = get_available_drives()
    logging.info(f"找到以下磁盘: {', '.join(drives)}")
    all_user_data_folders = []
    with ThreadPoolExecutor() as executor:
        for folders in executor.map(scan_for_user_data, drives):
            all_user_data_folders.extend(folders)
    logging.info(f"共找到 {len(all_user_data_folders)} 个User Data文件夹")
    total_deleted = 0
    total_size_freed = 0
    for folder in all_user_data_folders:
        deleted, size = delete_cache_in_user_data(folder)
        total_deleted += deleted
        total_size_freed += size
    logging.info(f"清理完成: 共删除 {total_deleted} 个cache文件夹")
    logging.info(f"释放空间: {total_size_freed/1024/1024:.2f} MB")
    print("\n清理摘要:")
    print(f"扫描了 {len(drives)} 个磁盘")
    print(f"找到 {len(all_user_data_folders)} 个User Data文件夹")
    print(f"删除了 {total_deleted} 个cache文件夹")
    print(f"释放了 {total_size_freed/1024/1024:.2f} MB空间")
    print("\n详细日志已保存到 cache_cleaner.log")
    input("\n按Enter键退出...")
if __name__ == "__main__":
    main() 