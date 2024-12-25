import tkinter as tk
from tkinter import filedialog
import requests
import hashlib
import time
import threading
import os

API_KEY_FILE = "api_key.txt"

def save_api_key():
    api_key = api_key_entry.get().strip()
    if api_key:
        with open(API_KEY_FILE, "w") as f:
            f.write(api_key)
        update_status("API ключ сохранен.")
        show_or_hide_api_key_fields()
    else:
        update_status("Пожалуйста, введите API ключ.")

def load_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as f:
            return f.read().strip()
    return ""

def get_file_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def scan_file(api_key, file_path):
    file_hash = get_file_hash(file_path)
    url_report = f"https://www.virustotal.com/vtapi/v2/file/report"
    params_report = {'apikey': api_key, 'resource': file_hash}
    response_report = requests.get(url_report, params=params_report, verify=False)
    if response_report.status_code == 204:
        return {"error": "Превышено ограничение на загрузку файлов. Пожалуйста, подождите некоторое время и попробуйте снова."}
    if response_report.status_code != 200:
        return {"error": f"Server returned status code {response_report.status_code}"}
    try:
        response_json = response_report.json()
    except ValueError:
        return {"error": "Invalid response from VirusTotal"}
    if response_json.get('response_code') == 0:
        # Если файл не был найден, загружаем его для сканирования
        url_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
        files = {'file': open(file_path, 'rb')}
        params_scan = {'apikey': api_key}
        response_scan = requests.post(url_scan, files=files, params=params_scan, verify=False)
        if response_scan.status_code == 204:
            return {"error": "Превышено ограничение на загрузку файлов. Пожалуйста, подождите некоторое время и попробуйте снова."}
        if response_scan.status_code != 200:
            return {"error": f"Server returned status code {response_scan.status_code}"}
        try:
            response_scan_json = response_scan.json()
        except ValueError:
            return {"error": "Invalid response from VirusTotal"}
        scan_id = response_scan_json.get('scan_id')
        return check_scan_status(api_key, scan_id)
    return response_json

def check_scan_status(api_key, scan_id):
    url_report = f"https://www.virustotal.com/vtapi/v2/file/report"
    params_report = {'apikey': api_key, 'resource': scan_id}
    while True:
        response_report = requests.get(url_report, params=params_report, verify=False)
        if response_report.status_code == 204:
            return {"error": "Превышено ограничение на загрузку файлов. Пожалуйста, подождите некоторое время и попробуйте снова."}
        if response_report.status_code != 200:
            return {"error": f"Server returned status code {response_report.status_code}"}
        try:
            result = response_report.json()
        except ValueError:
            return {"error": "Invalid response from VirusTotal"}
        if result.get('response_code') == 1:
            return result
        update_status("Идет сканирование, подождите 30 секунд...")
        time.sleep(30)

def upload_and_scan():
    file_path = filedialog.askopenfilename()
    if file_path:
        api_key = load_api_key()
        if not api_key:
            update_status("Пожалуйста, введите API ключ.")
            return
        update_status(f"Сканирование файла: {file_path}")
        threading.Thread(target=scan_and_display, args=(api_key, file_path)).start()

def scan_and_display(api_key, file_path):
    update_status(f"Идет сканирование файла: {file_path}")
    result = scan_file(api_key, file_path)
    update_status("Сканирование завершено")
    display_results(file_path, result)

def update_status(message):
    status_text.set(message)
def display_results(file_path, result):
    report_text.config(state=tk.NORMAL)
    report_text.delete(1.0, tk.END)

    report_text.insert(tk.END, f"Название файла: {file_path}\n", "header")

    if "error" in result:
        report_text.insert(tk.END, f"Ошибка: {result['error']}\n", "threats")
    else:
        positives = result['positives']
        total = result['total']

        if positives == 0:
            report_text.insert(tk.END, "Файл чист. Ни один антивирус не обнаружил угроз. 🎉\n", "clean")
        else:
            report_text.insert(tk.END, f"Обнаружено угроз: {positives} из {total}\n\n", "threats")
            report_text.insert(tk.END, "Проблемы:\n", "threats")
            for engine, details in result['scans'].items():
                if details['detected']:
                    report_text.insert(tk.END, f"- {engine}: {details['result']}\n", "threats")

        report_text.insert(tk.END, f"\nПолный отчет: {result['permalink']}", "link")
    report_text.config(state=tk.DISABLED)

def copy_text():
    root.clipboard_clear()
    root.clipboard_append(report_text.get("1.0", tk.END))
    root.update()  

def clear_text():
    report_text.config(state=tk.NORMAL)
    report_text.delete(1.0, tk.END)

def show_or_hide_api_key_fields():
    api_key = load_api_key()
    if api_key:
        api_key_label.pack_forget()
        api_key_entry.pack_forget()
        update_button.pack(pady=5)
    else:
        api_key_label.pack()
        api_key_entry.pack(pady=5)
        save_button.pack(pady=5)

def update_api_key():
    api_key_label.pack()
    api_key_entry.pack(pady=5)
    save_button.pack(pady=5)
    update_button.pack_forget()

def show_context_menu(event):
    context_menu.tk_popup(event.x_root, event.y_root)

root = tk.Tk()
root.title("VirusTotal File Scanner")
root.configure(bg="#2e2e2e")  # Устанавливаем темный фон

frame = tk.Frame(root, padx=10, pady=10, bg="#2e2e2e")
frame.pack(padx=10, pady=10)

api_key_label = tk.Label(frame, text="API ключ:", bg="#2e2e2e", fg="white")
api_key_entry = tk.Entry(frame, width=50)

# Создание контекстного меню
context_menu = tk.Menu(root, tearoff=0)
context_menu.add_command(label="Вставить", command=lambda: api_key_entry.event_generate('<<Paste>>'))
api_key_entry.bind("<Button-3>", show_context_menu)  # Привязка контекстного меню к правой кнопке мыши

save_button = tk.Button(frame, text="Сохранить ключ", command=save_api_key, bg="#4CAF50", fg="white")
update_button = tk.Button(frame, text="Обновить ключ", command=update_api_key, bg="#4CAF50", fg="white")

show_or_hide_api_key_fields()  # Проверка наличия API ключа при запуске

upload_button = tk.Button(frame, text="Загрузить файл", command=upload_and_scan, bg="#4CAF50", fg="white")
upload_button.pack(pady=5)

status_text = tk.StringVar()
status_label = tk.Label(frame, textvariable=status_text, wraplength=600, bg="#2e2e2e", fg="white")
status_label.pack(pady=5)

report_text = tk.Text(frame, wrap=tk.WORD, width=80, height=20, bg="#1c1c1c", fg="white")
report_text.pack(pady=10)
report_text.config(state=tk.DISABLED)

# Настройка стилей для выделений
report_text.tag_configure("header", foreground="white", font=("Helvetica", 12, "bold"))
report_text.tag_configure("clean", foreground="#4CAF50", font=("Helvetica", 11))
report_text.tag_configure("threats", foreground="red", font=("Helvetica", 11))
report_text.tag_configure("link", foreground="cyan", font=("Helvetica", 10, "underline"))

copy_button = tk.Button(frame, text="Копировать текст", command=copy_text, bg="#4CAF50", fg="white")
copy_button.pack(pady=5)

clear_button = tk.Button(frame, text="Очистить текст", command=clear_text, bg="#4CAF50", fg="white")
clear_button.pack(pady=5)

root.mainloop()