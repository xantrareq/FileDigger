import logging
from logging.handlers import RotatingFileHandler
import os
import sys

# Путь к файлу логов
def get_exe_directory():
    # Определяем путь к директории, где находится .exe или .py файл
    if getattr(sys, 'frozen', False):
        # Если приложение запущено как исполнимый файл
        base_path = os.path.dirname(sys.executable)  # Путь к временной exe
    else:
        # Для обычной разработки
        base_path = os.path.dirname(__file__)

    return base_path
BASE_DIR = get_exe_directory()

LOG_FILE = os.path.join(BASE_DIR, "app.log")



# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,  # Минимальный уровень логов для записи (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format="%(asctime)s [%(levelname)s] %(message)s",  # Формат сообщения
    datefmt="%Y-%m-%d %H:%M:%S",  # Формат времени
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=1024 * 1024, backupCount=5,encoding="utf-8"),  # Логи записываются в файл
        logging.StreamHandler()  # Логи также выводятся в консоль
    ]
)
logging.getLogger("PIL").setLevel(logging.WARNING)

# Функция для получения логгера
def get_logger(name):
    return logging.getLogger(name)
