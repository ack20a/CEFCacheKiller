import os
import string
import shutil
import logging
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import scrolledtext
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cache_cleaner.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
class CacheCleaner:
    def __init__(self):
        self.user_data_folders = []
        self.scan_results = {}
        self.total_deleted = 0
        self.total_size_freed = 0
        self.drives = []
    def get_available_drives(self):
        drives = []
        for drive in string.ascii_uppercase:
            if os.path.exists(f"{drive}:"):
                drives.append(f"{drive}:")
        self.drives = drives
        return drives
    def scan_for_user_data(self, drive, callback=None):
        user_data_folders = []
        if callback:
            callback(f"开始扫描磁盘 {drive}")
        logging.info(f"开始扫描磁盘 {drive}")
        try:
            for root, dirs, _ in os.walk(drive, topdown=True):
                dirs[:] = [d for d in dirs if d not in ["Windows", "$Recycle.Bin", "System Volume Information"]]
                if "User Data" in dirs:
                    user_data_path = os.path.join(root, "User Data")
                    user_data_folders.append(user_data_path)
                    if callback:
                        callback(f"找到User Data文件夹: {user_data_path}")
                    logging.info(f"找到User Data文件夹: {user_data_path}")
        except Exception as e:
            error_msg = f"扫描{drive}时出错: {str(e)}"
            if callback:
                callback(error_msg, is_error=True)
            logging.error(error_msg)
        return user_data_folders
    def scan_all_drives(self, progress_callback=None, finish_callback=None):
        drives = self.get_available_drives()
        if progress_callback:
            progress_callback(f"找到以下磁盘: {', '.join(drives)}")
        logging.info(f"找到以下磁盘: {', '.join(drives)}")
        self.user_data_folders = []
        self.scan_results = {}
        with ThreadPoolExecutor() as executor:
            for drive in drives:
                def drive_callback(message, is_error=False, drive=drive):
                    if progress_callback:
                        progress_callback(message, is_error)
                future = executor.submit(self.scan_for_user_data, drive, drive_callback)
                folders = future.result()
                self.user_data_folders.extend(folders)
                for folder in folders:
                    self.scan_results[folder] = self.find_cache_in_folder(folder, progress_callback)
        if progress_callback:
            progress_callback(f"扫描完成，共找到 {len(self.user_data_folders)} 个User Data文件夹")
        logging.info(f"共找到 {len(self.user_data_folders)} 个User Data文件夹")
        if finish_callback:
            finish_callback(self.scan_results)
    def find_cache_in_folder(self, folder_path, callback=None):
        cache_folders = []
        try:
            for root, dirs, _ in os.walk(folder_path):
                for dir_name in dirs:
                    if "cache" in dir_name.lower():
                        cache_path = os.path.join(root, dir_name)
                        try:
                            folder_size = sum(f.stat().st_size for f in Path(cache_path).glob('**/*') if f.is_file())
                            cache_folders.append((cache_path, folder_size))
                            if callback:
                                callback(f"找到cache文件夹: {cache_path} (大小: {folder_size/1024/1024:.2f} MB)")
                        except Exception as e:
                            if callback:
                                callback(f"计算{cache_path}大小时出错: {str(e)}", is_error=True)
                            logging.error(f"计算{cache_path}大小时出错: {str(e)}")
        except Exception as e:
            if callback:
                callback(f"查找{folder_path}中的cache时出错: {str(e)}", is_error=True)
            logging.error(f"查找{folder_path}中的cache时出错: {str(e)}")
        return cache_folders
    def delete_cache(self, progress_callback=None, finish_callback=None):
        self.total_deleted = 0
        self.total_size_freed = 0
        for folder, cache_list in self.scan_results.items():
            if progress_callback:
                progress_callback(f"正在清理 {folder} 中的缓存...")
            for cache_path, size in cache_list:
                try:
                    shutil.rmtree(cache_path)
                    self.total_deleted += 1
                    self.total_size_freed += size
                    if progress_callback:
                        progress_callback(f"已删除: {cache_path} (大小: {size/1024/1024:.2f} MB)")
                    logging.info(f"已删除: {cache_path} (大小: {size/1024/1024:.2f} MB)")
                except Exception as e:
                    error_msg = f"删除{cache_path}时出错: {str(e)}"
                    if progress_callback:
                        progress_callback(error_msg, is_error=True)
                    logging.error(error_msg)
        summary = {
            "drives_count": len(self.drives),
            "folders_count": len(self.user_data_folders),
            "deleted_count": self.total_deleted,
            "size_freed": self.total_size_freed
        }
        if progress_callback:
            progress_callback(f"清理完成: 共删除 {self.total_deleted} 个cache文件夹")
            progress_callback(f"释放空间: {self.total_size_freed/1024/1024:.2f} MB")
        logging.info(f"清理完成: 共删除 {self.total_deleted} 个cache文件夹")
        logging.info(f"释放空间: {self.total_size_freed/1024/1024:.2f} MB")
        if finish_callback:
            finish_callback(summary)
class CacheCleanerApp(ttk.Window):
    def __init__(self):
        super().__init__(title="浏览器缓存清理工具", themename="darkly")
        self.cleaner = CacheCleaner()
        self.scan_thread = None
        self.delete_thread = None
        self.scan_results = {}
        self.setup_ui()
    def setup_ui(self):
        self.geometry("800x600")
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=BOTH, expand=YES, padx=10, pady=10)
        title_label = ttk.Label(
            main_frame, 
            text="浏览器缓存清理工具", 
            font=("Arial", 16, "bold"),
            bootstyle="light"
        )
        title_label.pack(pady=10)
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=X, pady=10)
        self.scan_button = ttk.Button(
            button_frame, 
            text="扫描缓存", 
            command=self.start_scan, 
            bootstyle="primary",
            width=20
        )
        self.scan_button.pack(side=LEFT, padx=5)
        self.clean_button = ttk.Button(
            button_frame, 
            text="清理缓存", 
            command=self.start_clean, 
            bootstyle="danger",
            width=20,
            state=DISABLED
        )
        self.clean_button.pack(side=LEFT, padx=5)
        self.about_button = ttk.Button(
            button_frame, 
            text="关于", 
            command=self.show_about, 
            bootstyle="info",
            width=10
        )
        self.about_button.pack(side=LEFT, padx=5)
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=X, pady=10)
        ttk.Label(progress_frame, text="进度:").pack(side=LEFT)
        self.progress_bar = ttk.Progressbar(
            progress_frame, 
            bootstyle="success-striped",
            mode="indeterminate",
            length=200
        )
        self.progress_bar.pack(side=LEFT, fill=X, expand=YES, padx=5)
        self.stats_frame = ttk.LabelFrame(main_frame, text="统计信息", padding=10)
        self.stats_frame.pack(fill=X, pady=10)
        self.stats_var = {
            "drives": tk.StringVar(value="扫描的磁盘: 0"),
            "folders": tk.StringVar(value="User Data文件夹数: 0"),
            "caches": tk.StringVar(value="缓存文件夹数: 0"),
            "size": tk.StringVar(value="可释放空间: 0 MB")
        }
        for i, (key, var) in enumerate(self.stats_var.items()):
            ttk.Label(self.stats_frame, textvariable=var).grid(row=i//2, column=i%2, sticky="w", padx=5, pady=2)
        log_frame = ttk.LabelFrame(main_frame, text="日志", padding=10)
        log_frame.pack(fill=BOTH, expand=YES, pady=10)
        self.log_text = scrolledtext.ScrolledText(
            log_frame, 
            height=15, 
            wrap=tk.WORD,
            font=("Consolas", 9)
        )
        self.log_text.pack(fill=BOTH, expand=YES)
        self.log_text.config(state=DISABLED)
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=X, pady=5)
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=LEFT)
        author_label = ttk.Label(
            status_frame, 
            text="作者网站: https://ack20.eu.org/", 
            cursor="hand2",
            bootstyle="secondary"
        )
        author_label.pack(side=RIGHT)
        author_label.bind("<Button-1>", lambda e: self.open_website("https://ack20.eu.org/"))
        self.tag_configure()
    def tag_configure(self):
        self.log_text.tag_configure("error", foreground="red")
        self.log_text.tag_configure("info", foreground="white")
        self.log_text.tag_configure("success", foreground="green")
    def open_website(self, url):
        import webbrowser
        webbrowser.open(url)
    def show_about(self):
        about_window = ttk.Toplevel(title="关于")
        about_window.geometry("300x150")
        about_window.grab_set()
        info_frame = ttk.Frame(about_window, padding=20)
        info_frame.pack(fill=BOTH, expand=YES)
        ttk.Label(
            info_frame, 
            text="浏览器缓存清理工具",
            font=("Arial", 12, "bold"),
            bootstyle="light"
        ).pack(pady=(0, 10))
        ttk.Label(info_frame, text="作者: ack20").pack(pady=2)
        website_label = ttk.Label(
            info_frame, 
            text="网站: https://ack20.eu.org/",
            cursor="hand2",
            bootstyle="info"
        )
        website_label.pack(pady=2)
        website_label.bind("<Button-1>", lambda e: self.open_website("https://ack20.eu.org/"))
        ttk.Button(
            info_frame, 
            text="关闭", 
            command=about_window.destroy,
            bootstyle="secondary"
        ).pack(pady=(10, 0))
    def append_log(self, message, is_error=False, is_success=False):
        self.log_text.config(state=NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        last_line_start = self.log_text.index(f"end-1c linestart")
        last_line_end = self.log_text.index(f"end-1c")
        if is_error:
            self.log_text.tag_add("error", last_line_start, last_line_end)
        elif is_success:
            self.log_text.tag_add("success", last_line_start, last_line_end)
        else:
            self.log_text.tag_add("info", last_line_start, last_line_end)
        self.log_text.config(state=DISABLED)
        self.log_text.see(tk.END)
    def update_status(self, message):
        self.status_var.set(message)
    def start_scan(self):
        self.scan_button.config(state=DISABLED)
        self.clean_button.config(state=DISABLED)
        self.progress_bar.start()
        self.update_status("正在扫描...")
        self.log_text.config(state=NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=DISABLED)
        for var in self.stats_var.values():
            var.set(var.get().split(":")[0] + ": 0")
        self.scan_thread = threading.Thread(target=self.run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    def run_scan(self):
        self.cleaner.scan_all_drives(
            progress_callback=self.update_scan_progress,
            finish_callback=self.scan_finished
        )
    def update_scan_progress(self, message, is_error=False):
        self.append_log(message, is_error)
    def scan_finished(self, results):
        self.scan_results = results
        self.progress_bar.stop()
        total_caches = sum(len(caches) for caches in results.values())
        total_size = sum(size for caches in results.values() for _, size in caches)
        self.stats_var["drives"].set(f"扫描的磁盘: {len(self.cleaner.drives)}")
        self.stats_var["folders"].set(f"User Data文件夹数: {len(results)}")
        self.stats_var["caches"].set(f"缓存文件夹数: {total_caches}")
        self.stats_var["size"].set(f"可释放空间: {total_size/1024/1024:.2f} MB")
        self.scan_button.config(state=NORMAL)
        if total_caches > 0:
            self.clean_button.config(state=NORMAL)
            self.update_status(f"扫描完成，找到 {total_caches} 个缓存文件夹，可释放 {total_size/1024/1024:.2f} MB 空间")
            self.append_log(f"扫描完成，找到 {total_caches} 个缓存文件夹，可释放 {total_size/1024/1024:.2f} MB 空间", is_success=True)
        else:
            self.update_status("扫描完成，未找到任何缓存文件夹")
            self.append_log("扫描完成，未找到任何缓存文件夹", is_success=True)
    def start_clean(self):
        self.scan_button.config(state=DISABLED)
        self.clean_button.config(state=DISABLED)
        self.progress_bar.start()
        self.update_status("正在清理缓存...")
        self.delete_thread = threading.Thread(target=self.run_clean)
        self.delete_thread.daemon = True
        self.delete_thread.start()
    def run_clean(self):
        self.cleaner.delete_cache(
            progress_callback=self.update_clean_progress,
            finish_callback=self.clean_finished
        )
    def update_clean_progress(self, message, is_error=False):
        self.append_log(message, is_error)
    def clean_finished(self, summary):
        self.progress_bar.stop()
        self.stats_var["drives"].set(f"扫描的磁盘: {summary['drives_count']}")
        self.stats_var["folders"].set(f"User Data文件夹数: {summary['folders_count']}")
        self.stats_var["caches"].set(f"已清理缓存数: {summary['deleted_count']}")
        self.stats_var["size"].set(f"已释放空间: {summary['size_freed']/1024/1024:.2f} MB")
        self.scan_button.config(state=NORMAL)
        self.clean_button.config(state=DISABLED)
        msg = f"清理完成，已删除 {summary['deleted_count']} 个缓存文件夹，释放 {summary['size_freed']/1024/1024:.2f} MB 空间"
        self.update_status(msg)
        self.append_log(msg, is_success=True)
if __name__ == "__main__":
    app = CacheCleanerApp()
    app.mainloop()