import tkinter as tk
from interface import create_tray_icon, open_api_key_window, open_scanner_window
import win32event
import win32api
import winerror
import sys

# Уникальное имя мьютекса для приложения
MUTEX_NAME = "FileDigger"

# Попытка создать мьютекс. Это механизм синхронизации, который используется для предотвращения доступа
mutex = win32event.CreateMutex(None, False, MUTEX_NAME)
print(mutex)
# Проверяем, запущено ли приложение
if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
    # Приложение уже запущено
    print("Приложение уже запущено.")
    sys.exit(0)
elif not mutex:
    print("Ошибка при создании мьютекса.")
    sys.exit(1)

# Обработка закрытия
def on_closing():
    # Скрытие главного окна
    root.withdraw()

# Создание главного окна
root = tk.Tk()

# Скрытие главного окна
root.withdraw()

# Обработка закрытия
root.protocol("WM_DELETE_WINDOW", on_closing)

# Создание tray иконки
create_tray_icon(root, open_api_key_window, open_scanner_window)

# Главный цикл
root.mainloop()
