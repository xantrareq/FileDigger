import os
import hashlib
import requests
from notifypy import Notify





# Определяем путь к директории скрипта
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Полные пути к файлам
API_KEY_FILE = os.path.join(BASE_DIR, "api_key.env")



def load_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as f:
            return f.read().strip()
    return ""

def save_api_key(api_key):
    with open(API_KEY_FILE, "w") as f:
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
        return {"error": f"Ошибка сервера: {response_report.status_code}"}
    response_json = response_report.json()
    if response_json.get('response_code') == 0:
        return {"positives": 0, "total": 0, "scans": {}, "permalink": ""}
    return response_json



def scan_and_display(api_key, file_path, ismon, open_application, update_status):
    update_status(f"Сканирование файла: {file_path}")
    result = scan_file(api_key, file_path)
    
    detailed_threat = ""
    if result.get("positives", 0) > 0:
 
        detailed_threat += f"Угроза в файле: {file_path}\n"
        detailed_threat += f"Обнаружено угроз: {result['positives']} из {result['total']}\n"
        for engine, details in result['scans'].items():
            if details['detected']:
                detailed_threat += f"- {engine}: {details['result']}\n"
        detailed_threat += f"Ссылка на отчет: {result.get('permalink', '')}\n"

        update_status(f"Обнаружена угроза в файле: {file_path}")



        # Показываем уведомление в системном трее
        notification = Notify()
        notification.application_name = "FileDigger"
        notification.title = "Угроза"
        notification.message = f"Обнаружена угроза в файле: {file_path}"
        notification.icon = os.path.join(BASE_DIR, "notify.png")
        notification.send(block=False)

        open_application()
        return detailed_threat, 0

    else:
        update_status(f"Файл {file_path} безопасен.")
        detailed_threat += f"Файл {file_path} безопасен. Все проверки пройдены успешно!"
        return detailed_threat, 1



