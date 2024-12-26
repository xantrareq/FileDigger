import os
import hashlib
import requests

from notifypy import Notify
import json
from datetime import datetime
import sys



# Определяем путь к директории скрипта
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

# Полные пути к файлам
API_KEY_FILE = os.path.join(BASE_DIR, "api_key.env")
LAST_THREATS_FILE = os.path.join(BASE_DIR, "last_threats.env")



def load_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as f:
            return f.read().strip()
    return ""

def save_api_key(api_key):
    with open(API_KEY_FILE, "w") as f:
        print(f"API ключ успешно сохранен в {API_KEY_FILE}")

        f.write(api_key)


def get_file_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def scan_file(api_key, file_path):
    file_hash = get_file_hash(file_path)
    url_report = "https://www.virustotal.com/vtapi/v2/file/report"
    params_report = {'apikey': api_key, 'resource': file_hash}
    response_report = requests.get(url_report, params=params_report, verify=True)

    if response_report.status_code == 204:
        return {"error": "Превышено ограничение на запросы. Подождите немного."}
    if response_report.status_code != 200:
        return 200
    response_json = response_report.json()
    if response_json.get('response_code') == 0:
        return {"positives": 0, "total": 0, "scans": {}, "permalink": ""}
    
    return response_json



def scan_and_display(api_key, file_path, ismon, open_application, update_status):
    update_status(f"Сканирование файла: {file_path}")
    result = scan_file(api_key, file_path)
    detailed_threat = ""

    if result == 200:
        return "Не получилось корректно отработать. Проверьте ключ", 2
    elif result.get("positives", 0) > 0:
        detailed_threat = f"Угроза в файле: {file_path}\n"
        detailed_threat += f"Обнаружено угроз: {result['positives']} из {result['total']}\n"
        for engine, details in result['scans'].items():
            if details['detected']:
                detailed_threat += f"- {engine}: {details['result']}\n"
        detailed_threat += f"Ссылка на отчет: {result.get('permalink', '')}\n"
 
        update_status(f"Обнаружена угроза в файле: {file_path}")

        # Сохранение угрозы в файл
        if(ismon == 1):
            save_threat_to_file(detailed_threat)

        # Обновление report_text после сохранения новой угрозы
        from interface import load_last_threats
        load_last_threats()
        if(ismon == 1):
            # Показываем уведомление в системном трее
            notification = Notify()
            notification.application_name = "FileDigger"
            notification.title = "Угроза"
            notification.message = f"Обнаружена угроза в файле: {file_path}"
            notification.icon = os.path.join(os.path.dirname(__file__), "notify.png")
            notification.send(block=False)

        open_application()
        return detailed_threat, 0

    else:
        update_status(f"Файл {file_path} безопасен.")
        return f"Файл {file_path} безопасен. Все проверки пройдены успешно!", 1




def save_threat_to_file(detailed_threat):
    # Добавляем detailed_threat в файл LAST_THREATS_FILE, сохраняя максимум 20 записей.
    threats = []

    # Загружаем текущие угрозы из файла, если он существует
    if os.path.exists(LAST_THREATS_FILE):
        with open(LAST_THREATS_FILE, "r", encoding="utf-8") as file:
            try:
                threats = json.load(file)
            except json.JSONDecodeError:
                threats = []

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    detailed_threat_with_time = f"[{current_time}] {detailed_threat}"

    # Добавляем новую угрозу с временем
    threats.append(detailed_threat_with_time)

    # Оставляем только последние 20 записей
    if len(threats) > 20:
        threats.pop(0)  # Удаляем самую раннюю запись

    # Сохраняем обновлённый список угроз обратно в файл
    with open(LAST_THREATS_FILE, "w", encoding="utf-8") as file:
        json.dump(threats, file, ensure_ascii=False, indent=2)

