import tkinter as tk
from pystray import Icon, Menu, MenuItem
from PIL import Image, ImageDraw
import threading
from scanner import load_api_key, save_api_key, scan_and_display
import os
from tkinter import filedialog
from datetime import datetime


scanner_window_open = False
api_key_window_open = False
monitor_window_open = False 


BASE_DIR = os.path.dirname(os.path.abspath(__file__))




def update_status(message):
    print(message)  

def create_tray_icon(root, open_api_key_window, open_scanner_window):
    def quit_application(icon):

        icon.stop()
        root.quit()
        root.destroy()

  
    # image = Image.new('RGB', (64, 64), "blue")
    image = Image.open(os.path.join(BASE_DIR, "icon.png"))
    ImageDraw.Draw(image)
    # draw.rectangle((0, 0, 63, 63), fill="blue")
    # draw.text((25, 30), "V", fill="white")

    menu = Menu(
        MenuItem("API ключ", lambda: open_api_key_window(root)),
        MenuItem("Сканер", lambda: open_scanner_window(root)),
        MenuItem("Выход", quit_application)
    )
    icon = Icon("file_digger_icon", image, "FileDigger", menu)
    threading.Thread(target=icon.run, daemon=True).start()
        


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
        


    symbs = "@#%^&*()_+[]{]|;:',.<>?/~-="
        
    window = tk.Toplevel(root)
    window.configure(bg="#2e2e2e")

    
    window.title("File Digger API ключ")
    
    icon = tk.PhotoImage(file=(os.path.join(BASE_DIR, "icon.png")))
    window.iconphoto(False, icon)
    
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
                update_status("Пожалуйста, введите API ключ.")
                return
            threat,safety = scan_and_display(api_key, file_path, 0, lambda: None, update_status)
            
            report_text.tag_configure("red", foreground="#ff0d0d")
            report_text.tag_configure("green", foreground="green")
            report_text.tag_configure("white", foreground="white")
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            report_text.insert(tk.END, f"{current_time}\n", "white")
            if(safety):
                report_text.insert(tk.END, f"{threat}\n", "green")
            else:
                report_text.insert(tk.END, f"{threat}\n", "red")

    window = tk.Toplevel(root)
    window.configure(bg="#2e2e2e")
    window.protocol("WM_DELETE_WINDOW", on_close)
    window.title("File Digger Сканер")
    icon = tk.PhotoImage(file=(os.path.join(BASE_DIR, "icon.png")))
    window.iconphoto(False, icon)
    window.geometry("600x400")
    tk.Button(window, text="Выбрать файл для сканирования", command=upload_and_scan,fg="white", bg = "#2e2e2e").pack(pady=10)
    global report_text
    report_text = tk.Text(window, wrap=tk.WORD, width=50, height=55,fg="white", bg = "#2e2e2e")
    report_text.pack(pady=10)



