import tkinter as tk
from pystray import Icon, Menu, MenuItem
from PIL import Image, ImageDraw
import threading
from scanner import load_api_key, save_api_key, scan_and_display
from monitor import FolderMonitor
from tkinter import filedialog
import json
import os
from notifypy import Notify
from datetime import datetime
from logger import get_logger

logger = get_logger(__name__)

scanner_window_open = False
api_key_window_open = False
monitor_window_open = False 


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LAST_THREATS_FILE = os.path.join(BASE_DIR, "last_threats.env")

folder_monitor = FolderMonitor()

def update_status(message):
    print(message)  

def create_tray_icon(root, open_api_key_window, open_scanner_window):
    def quit_application(icon):

        icon.stop()
        root.quit()
        root.destroy()

  
    logger.info("Запуск трея")
    try:
        image = Image.open(os.path.join(BASE_DIR, "icon.png"))
        ImageDraw.Draw(image)

        
        menu = Menu(
            MenuItem("API ключ", lambda: open_api_key_window(root)),
            MenuItem("Сканер", lambda: open_scanner_window(root)),
            MenuItem("Мониторинг", lambda: open_monitor_window(root)),
            MenuItem("Выход", quit_application)
        )
        icon = Icon("file_digger_icon", image, "FileDigger", menu)
        threading.Thread(target=icon.run, daemon=True).start()
    except Exception as e:
        logger.error(f"Ошибка при запуске трея: {e}")
        


def open_api_key_window(root):
    
    global api_key_window_open
    if api_key_window_open:
        return
    api_key_window_open = True
    

    def save_and_close():
        api_key = api_key_entry.get()
        if api_key:
            save_api_key(api_key)
            update_status("API ключ успешно сохранен.")
            global api_key_window_open
            api_key_window_open = False
            window.destroy()
        else:
            update_status("Ошибка: API ключ не может быть пустым.")

    def show_api():
        if api_key_label.cget("text") == symbs:
            api_key_label.config(text=api_key)
            show_button.config(text="Скрыть")
        else:
            api_key_label.config(text=symbs)
            show_button.config(text="Отобразить")
        

    logger.info("Запуск Api-window")
    try:
        symbs = "@#%^&*()_+[]{]|;:',.<>?/~-="
            
        window = tk.Toplevel(root)
        window.configure(bg="#2e2e2e")

        
        window.title("File Digger API ключ")
        
        icon = tk.PhotoImage(file=(os.path.join(BASE_DIR, "icon.png")))
        window.iconphoto(True, icon)
        
        window.geometry("700x300")
        api_key = load_api_key()
        if not api_key:
            tk.Label(window, text="Введите API ключ:",fg="white", bg = "#2e2e2e").pack(pady=10)
            api_key_entry = tk.Entry(window, width=30)
            api_key_entry.pack(pady=10)
            tk.Button(window, text="Сохранить", command=save_and_close).pack(pady=10)
        else:
            tk.Label(window, text="API ключ введен. Вы можете изменить его",fg="white", bg = "#2e2e2e").pack(pady=10)
        
            frame = tk.Frame(window)
            frame.configure(bg="#2e2e2e")
            frame.pack(pady=10)

            api_key_label = tk.Label(frame, text=symbs, font=("Arial", 10),fg="white", bg = "#2e2e2e")
            api_key_label.grid(row=0, column=0, padx=5)


            show_button = tk.Button(frame, text="Отобразить", command=show_api,fg="white", bg = "#2e2e2e")
            show_button.grid(row=0, column=1, padx=5)
            
            api_key_entry = tk.Entry(window, width=30,fg="white", bg = "#2e2e2e")

            api_key_entry.pack(pady=10)
            tk.Button(window, text="Сохранить", command=save_and_close,fg="white", bg = "#2e2e2e").pack(pady=10)
    except Exception as e:
        logger.error(f"Ошибка при запуске апи ключа: {e}")

def open_scanner_window(root):
    
    global scanner_window_open
    if scanner_window_open:
        return
    scanner_window_open = True
    
    def on_close():
        global scanner_window_open
        scanner_window_open = False
        window.destroy()
    
    def upload_and_scan():
        file_path = tk.filedialog.askopenfilename()
        if file_path:
            api_key = load_api_key()
            if not api_key:
                notification = Notify()
                notification.application_name = "FileDigger"
                notification.title = "API ключ"
                notification.message = "Вы не ввели api ключ"
                notification.icon = os.path.join(BASE_DIR, "notify.png")
                notification.send(block=False)
                return
            threat,safety = scan_and_display(api_key, file_path, 0, lambda: None, update_status)
            
            report_text.tag_configure("red", foreground="#ff0d0d")
            report_text.tag_configure("green", foreground="green")
            report_text.tag_configure("white", foreground="white")
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if(safety == 1):
                report_text.insert("1.0", f"{threat}\n", "green")
            elif(safety == 0):
                report_text.insert("1.0", f"{threat}\n", "red")
            else:
                report_text.insert("1.0", f"{threat}\n", "orange")
            report_text.insert("1.0", f"{current_time}\n", "white")
    logger.info("Запуск scan-window")
    try:
        window = tk.Toplevel(root)
        window.configure(bg="#2e2e2e")
        window.protocol("WM_DELETE_WINDOW", on_close)
        window.title("File Digger Сканер")
        icon = tk.PhotoImage(file=(os.path.join(BASE_DIR, "icon.png")))
        window.iconphoto(True, icon)
        window.geometry("600x400")
        tk.Button(window, text="Выбрать файл для сканирования", command=upload_and_scan,fg="white", bg = "#2e2e2e").pack(pady=10)
        global report_text
        report_text = tk.Text(window, wrap=tk.WORD, width=50, height=55,fg="white", bg = "#2e2e2e")
        report_text.pack(pady=10)
    except Exception as e:
        logger.error(f"Ошибка при запуске сканера: {e}")



def load_last_threats():
    if monitor_window_open:
        #Загружаем последние угрозы из файла и отображает их в report_text в обратном порядке.
        if os.path.exists(LAST_THREATS_FILE):
            with open(LAST_THREATS_FILE, "r", encoding="utf-8") as file:
                try:
                    threats = json.load(file)
                    # Отображаем угрозы в обратном порядке
                    report_text.delete("1.0", tk.END)  # Очищаем текстовое поле перед вставкой
                    for threat in reversed(threats):
                        report_text.insert(tk.END, threat + "\n\n")
                except json.JSONDecodeError:
                    report_text.insert(tk.END, "Ошибка при загрузке файла угроз.\n")
        else:
            report_text.insert(tk.END, "Файл с угрозами не найден.\n")


def open_monitor_window(root):
    
    global monitor_window_open
    if monitor_window_open:
        return  # Если окно уже открыто, не создаём его снова

    monitor_window_open = True
  
    
    def on_close():
        global monitor_window_open
        monitor_window_open = False
        window.destroy()
        
    

    def select_folder():
        folder_path = filedialog.askdirectory()  # Используем filedialog для выбора папки
        if folder_path:
            api_key = load_api_key()
            if not api_key:
                notification = Notify()
                notification.application_name = "FileDigger"
                notification.title = "API ключ"
                notification.message = "Вы не ввели api ключ"
                notification.icon = os.path.join(BASE_DIR, "notify.png")
                notification.send(block=False)
                return

            # Проверяем, есть ли уже эта папка в мониторинге
            if folder_path in folder_monitor.monitors:
                update_status(f"Папка {folder_path} уже добавлена для мониторинга.")
                return

            # Если в списке мониторингов больше 2 папок, сдвигаем список
            current_folders = list(folder_monitor.monitors.keys())
            if len(current_folders) >= 3:
                # Останавливаем мониторинг для самой старой папки
                oldest_folder = current_folders[0]
                folder_monitor.stop_monitoring(oldest_folder)
                update_status(f"Мониторинг папки {oldest_folder} остановлен, так как достигнут лимит.")

            # Запускаем мониторинг для новой папки
            update_status(f"Запуск мониторинга для папки: {folder_path}")
            folder_monitor.start_monitoring(
                folder_path, api_key, 
                lambda api_key, path: scan_and_display(api_key, path, 1, lambda: None, update_status), 
                update_status
            )

            # Проверяем содержимое folder_monitor после добавления папки
            update_status(f"Текущий список мониторингов: {list(folder_monitor.monitors.keys())}")

            # После добавления папки обновляем отображение активных мониторингов
            update_active_monitors()


    def remove_monitoring(folder_path):
        update_status(f"Удаление мониторинга для папки: {folder_path}")
        folder_monitor.stop_monitoring(folder_path, update_status)
        
        # Проверяем содержимое folder_monitor после удаления папки
        update_status(f"Текущий список мониторингов после удаления: {list(folder_monitor.monitors.keys())}")
        
        update_active_monitors()  # После удаления обновляем список активных папок
    def update_active_monitors():


        # Очищаем текущий список
        for widget in active_monitors_frame.winfo_children():
            widget.destroy()

        # Добавляем все активные мониторинги
        for folder in folder_monitor.monitors.keys():

            
            frame = tk.Frame(active_monitors_frame, bg="#2e2e2e")
            frame.configure(bg="#2e2e2e")
            frame.pack(pady=1, fill=tk.X)

            label = tk.Label(frame, text=f"Мониторинг: {folder}", fg="white", bg="#2e2e2e", bd=0, highlightthickness=0)
            label.pack(side=tk.LEFT)

            remove_button = tk.Button(frame, text="Удалить", command=lambda folder=folder: remove_monitoring(folder), fg="white", bg="#7e7e7e", bd=0, highlightthickness=0)
            remove_button.pack(side=tk.LEFT, padx=10)
            
            
    logger.info("Запуск monitoring-window")
    try:
        window = tk.Toplevel(root)
        window.configure(bg="#2e2e2e")
        window.protocol("WM_DELETE_WINDOW", on_close)
        window.title("File Digger мониторинг")
        icon = tk.PhotoImage(file=(os.path.join(BASE_DIR, "icon.png")))
        window.iconphoto(True, icon)
        window.geometry("600x500")
        
        # Кнопка для выбора папки для мониторинга
        tk.Button(window, text="Выбрать папку для мониторинга", command=select_folder,fg="white", bg = "#2e2e2e").pack(pady=10)

        # Отображаем все активные мониторинги
        active_monitors_frame = tk.Frame(window)
        active_monitors_frame.pack(pady=10)

        # Текстовое поле для отчёта
        global report_text
        report_text = tk.Text(window, wrap=tk.WORD, width=70, height=20)
        report_text.configure(bg="#2e2e2e",fg="#fca4a4")
        report_text.pack(pady=10)
        


    
        # Изначально показываем все активные мониторинги
        load_last_threats()
        update_active_monitors()
    except Exception as e:
        logger.error(f"Ошибка при запуске мониторинга: {e}")

