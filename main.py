import tkinter as tk
from interface import create_tray_icon, open_api_key_window, open_scanner_window


#Обработка закрытия
def on_closing():
    #Скрытие главного окна
    root.withdraw()  

#Создание главного окна
root = tk.Tk()


#Скрытие главного окна
root.withdraw()

#Обработка закрытия
root.protocol("WM_DELETE_WINDOW", on_closing)


#Создание tray иконки
create_tray_icon(root, open_api_key_window, open_scanner_window)

#Главный цикл
root.mainloop()