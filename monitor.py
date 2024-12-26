import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scanner import load_api_key
from scanner import scan_and_display

import json
import os
import sys

def get_exe_directory():
    # Определяем путь к директории, где находится .exe или .py файл
    if getattr(sys, 'frozen', False):
        # Если приложение запущено как исполнимый файл
        base_path = os.path.dirname(sys.executable)  # Путь к exe
    else:
        # Для обычной разработки
        base_path = os.path.dirname(__file__)

    return base_path

BASE_DIR = get_exe_directory()

MONITORING_FILE = os.path.join(BASE_DIR, "monitoring.json")

def load_monitored_folders():
    #Загружаем список папок для мониторинга из файла.
    if os.path.exists(MONITORING_FILE):
        with open(MONITORING_FILE, "r") as f:
            return json.load(f)
    return []  # Если файл не найден, возвращаем пустой список

def save_monitored_folders(folders):
    #Сохраняем список папок для мониторинга в файл.
    with open(MONITORING_FILE, "w") as f:
        json.dump(folders, f)



def update_status(message):
    print(message)

    
class FolderEventHandler(FileSystemEventHandler):
    def __init__(self, api_key, scan_callback, delay=1):
        self.api_key = api_key
        self.scan_callback = scan_callback
        self.delay = delay

    def on_created(self, event):
        if not event.is_directory:
            time.sleep(self.delay)
            self.scan_callback(self.api_key, event.src_path)

class FolderMonitor:
    def __init__(self, delay=1):
        self.monitors = {}
        self.delay = delay
        self.last_monitored_folder = None
        # Загружаем активные папки при старте и начинаем их мониторинг
        self.load_monitors()

    def load_monitors(self):
        #Загружаем активные мониторинги из файла и восстанавливает их.

        monitored_folders = load_monitored_folders()  # Функция для загрузки папок из файла
        for folder_path in monitored_folders:
            if os.path.exists(folder_path):  # Проверяем, существует ли папка
                api_key = load_api_key()  # Загрузить API ключ
                if api_key:
                    # Запуск мониторинга для каждой папки
                    
                    self.start_monitoring(folder_path, api_key, 
                                           lambda api_key, path: scan_and_display(api_key, path, 1, lambda: None, update_status), 
                                           update_status)

    def start_monitoring(self, folder_path, api_key, scan_callback, update_status_callback):
        #Начинаем мониторинг папки.

        if folder_path in self.monitors:

            return  # Если мониторинг уже работает, не начинаем новый

        event_handler = FolderEventHandler(api_key, scan_callback, delay=self.delay)
        observer = Observer()
        observer.schedule(event_handler, folder_path, recursive=False)
        observer.start()

        
        self.monitors[folder_path] = observer
        self.last_monitored_folder = folder_path
        update_status_callback(f"Мониторинг папки {folder_path} запущен.")
 

        # Сохраняем активные мониторинги в файл
        self.save_monitors()

    def stop_monitoring(self, folder_path, update_status_callback=None):
        #Останавливаем мониторинг для папки.
        if folder_path in self.monitors:
            self.monitors[folder_path].stop()
            self.monitors[folder_path].join()
            del self.monitors[folder_path]
            if update_status_callback:
                update_status_callback(f"Мониторинг для папки {folder_path} остановлен.")
            # Сохраняем активные мониторинги в файл
            self.save_monitors()

    def save_monitors(self):
        #Сохраняем список активных папок в файл.
        monitored_folders = list(self.monitors.keys())
        save_monitored_folders(monitored_folders)  # Функция для сохранения папок в файл