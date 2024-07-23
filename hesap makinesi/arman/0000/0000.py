"""
import tkinter as tk
from tkinter import messagebox

class HesapMakinesi:
    def __init__(self, root):
        self.root = root
        self.root.title("Hesap Makinesi")

        # Sonuç ekranı
        self.result_label = tk.Label(root, text="", anchor="e", bg="white", padx=10, pady=10, font=("Arial", 14))
        self.result_label.grid(row=0, column=0, columnspan=4)

        # Butonlar
        buttons = [
            '7', '8', '9', '/',
            '4', '5', '6', '*',
            '1', '2', '3', '-',
            '0', '.', '=', '+'
        ]

        # Butonları yerleştirme
        r = 1
        c = 0
        for button_text in buttons:
            tk.Button(root, text=button_text, width=10, height=3, command=lambda text=button_text: self.button_click(text)).grid(row=r, column=c)
            c += 1
            if c > 3:
                c = 0
                r += 1

        # Temizle butonu
        tk.Button(root, text="C", width=10, height=3, command=self.clear).grid(row=r, column=0, columnspan=2)
        # Geri sil butonu
        tk.Button(root, text="<-", width=10, height=3, command=self.backspace).grid(row=r, column=2, columnspan=2)

    def button_click(self, text):
        current = self.result_label.cget("text")

        if text == "=":
            try:
                result = eval(current)
                self.result_label.config(text=result)
            except Exception as e:
                messagebox.showerror("Hata", "Geçersiz işlem!")
        elif text == "C":
            self.clear()
        elif text == "<-":
            self.backspace()
        else:
            self.result_label.config(text=current + text)

    def clear(self):
        self.result_label.config(text="")

    def backspace(self):
        current = self.result_label.cget("text")
        self.result_label.config(text=current[:-1])

if __name__ == "__main__":
    root = tk.Tk()
    app = HesapMakinesi(root)
    root.mainloop() 


#normal hali
import tkinter as tk
from tkinter import messagebox


todo_list = []


def ekle_gorev():
    yeni_gorev = entry_gorev.get()
    if yeni_gorev:
        todo_list.append(yeni_gorev)
        listeyi_guncelle()
        messagebox.showinfo("Başarılı", f"'{yeni_gorev}' görevi listeye eklendi.")
        entry_gorev.delete(0, tk.END)
    else:
        messagebox.showwarning("Uyarı", "Lütfen bir görev girin.")


def gorevleri_listele():
    if not todo_list:
        messagebox.showinfo("Bilgi", "Listede hiç görev bulunmuyor.")
    else:
        listeyi_guncelle()


def gorev_sil():
    try:
        index = int(entry_sil.get()) - 1
        if index >= 0 and index < len(todo_list):
            silinen_gorev = todo_list.pop(index)
            listeyi_guncelle()
            messagebox.showinfo("Başarılı", f"'{silinen_gorev}' görevi listeden silindi.")
            entry_sil.delete(0, tk.END)
        else:
            messagebox.showwarning("Uyarı", "Geçersiz indeks. Lütfen doğru bir indeks giriniz.")
    except ValueError:
        messagebox.showwarning("Uyarı", "Lütfen bir sayı girin.")


def tum_gorevleri_sil():
    if not todo_list:
        messagebox.showinfo("Bilgi", "Listede hiç görev bulunmuyor.")
    else:
        todo_list.clear()
        listeyi_guncelle()
        messagebox.showinfo("Başarılı", "Tüm görevler silindi.")


def listeyi_guncelle():
    listbox.delete(0, tk.END)
    for index, gorev in enumerate(todo_list, start=1):
        listbox.insert(tk.END, f"{index}. {gorev}")


root = tk.Tk()
root.title("Arman To-Do List")


frame = tk.Frame(root)
frame.pack(padx=20, pady=20)


label_baslik = tk.Label(frame, text="Arman TO-DO List", font=("Helvetica", 16, "bold"))
label_baslik.grid(row=0, column=0, columnspan=2, pady=10)


label_gorev = tk.Label(frame, text="Görev girin:")
label_gorev.grid(row=1, column=0, sticky="w")

entry_gorev = tk.Entry(frame, width=30)
entry_gorev.grid(row=1, column=1, padx=10)


button_ekle = tk.Button(frame, text="Ekle", command=ekle_gorev)
button_ekle.grid(row=1, column=2, padx=10)


button_tum_sil = tk.Button(frame, text="Tümünü Sil", command=tum_gorevleri_sil)
button_tum_sil.grid(row=2, column=1, pady=10)


label_liste = tk.Label(frame, text="Görevler:")
label_liste.grid(row=3, column=0, sticky="w", pady=10)

listbox = tk.Listbox(frame, width=40, height=10)
listbox.grid(row=4, column=0, columnspan=3, pady=5)


root.mainloop()


import tkinter as tk
from tkinter import messagebox


todo_list = []


def ekle_gorev():
    yeni_gorev = entry_gorev.get()
    if yeni_gorev:
        todo_list.append(yeni_gorev)
        listeyi_guncelle()
        messagebox.showinfo("Başarılı", f"'{yeni_gorev}' görevi listeye eklendi.")
        entry_gorev.delete(0, tk.END)
    else:
        messagebox.showwarning("Uyarı", "Lütfen bir görev girin.")


def gorevleri_listele():
    if not todo_list:
        messagebox.showinfo("Bilgi", "Listede hiç görev bulunmuyor.")
    else:
        listeyi_guncelle()


def gorev_sil():
    try:
        index = int(entry_sil.get()) - 1
        if index >= 0 and index < len(todo_list):
            silinen_gorev = todo_list.pop(index)
            listeyi_guncelle()
            messagebox.showinfo("Başarılı", f"'{silinen_gorev}' görevi listeden silindi.")
            entry_sil.delete(0, tk.END)
        else:
            messagebox.showwarning("Uyarı", "Geçersiz indeks. Lütfen doğru bir indeks giriniz.")
    except ValueError:
        messagebox.showwarning("Uyarı", "Lütfen bir sayı girin.")


def tum_gorevleri_sil():
    if not todo_list:
        messagebox.showinfo("Bilgi", "Listede hiç görev bulunmuyor.")
    else:
        todo_list.clear()
        listeyi_guncelle()
        messagebox.showinfo("Başarılı", "Tüm görevler silindi.")


def listeyi_guncelle():
    listbox.delete(0, tk.END)
    for index, gorev in enumerate(todo_list, start=1):
        listbox.insert(tk.END, f"{index}. {gorev}")


def secili_gorev():
    try:
        index = listbox.curselection()[0]
        return index
    except IndexError:
        return None


def gorev_sec_ve_sil():
    index = secili_gorev()
    if index is not None:
        silinen_gorev = todo_list.pop(index)
        listeyi_guncelle()
        messagebox.showinfo("Başarılı", f"'{silinen_gorev}' görevi listeden silindi.")
    else:
        messagebox.showwarning("Uyarı", "Lütfen silmek istediğiniz bir görev seçin.")


root = tk.Tk()
root.title("Arman To-Do List")


frame = tk.Frame(root)
frame.pack(padx=20, pady=20)


label_baslik = tk.Label(frame, text="Arman TO-DO List", font=("Helvetica", 16, "bold"))
label_baslik.grid(row=0, column=0, columnspan=3, pady=10)


label_gorev = tk.Label(frame, text="Görev girin:")
label_gorev.grid(row=1, column=0, sticky="w")

entry_gorev = tk.Entry(frame, width=30)
entry_gorev.grid(row=1, column=1, padx=10)


button_ekle = tk.Button(frame, text="Ekle", command=ekle_gorev)
button_ekle.grid(row=1, column=2, padx=10)


button_tum_sil = tk.Button(frame, text="Tümünü Sil", command=tum_gorevleri_sil)
button_tum_sil.grid(row=2, column=1, pady=10)


label_liste = tk.Label(frame, text="Görevler:")
label_liste.grid(row=3, column=0, sticky="w", pady=10)

listbox = tk.Listbox(frame, width=40, height=10)
listbox.grid(row=4, column=0, columnspan=3, pady=5)


button_sil = tk.Button(frame, text="Seçileni Sil", command=gorev_sec_ve_sil)
button_sil.grid(row=5, column=0, pady=10)


root.mainloop()




import requests

def main():
    base_currency = input("Lütfen döviz kodunu girin (Örneğin, USD, EUR): ").upper()
    amount = float(input("Lütfen miktarı girin (Varsayılan olarak 0 girilecektir): ") or 0.0)
    
    url = f"https://www.floatrates.com/daily/{base_currency}.json"
    response = requests.get(url)
    data = response.json()
    
    print(f"\nDöviz kurları {base_currency} bazında:")
    print("Kod\t\t\tİsim\t\t\tAlış\t\t\tSatış")
    print("="*80)
    
    if base_currency in data.keys():
        print_currency_row(base_currency, data[base_currency], amount)
    
    for currency, rate_info in data.items():
        if currency != base_currency:
            print_currency_row(currency, rate_info, amount)

def print_currency_row(currency, rate_info, amount):
    name = rate_info['name']
    buy_rate = rate_info['rate_float']
    sell_rate = rate_info['inverseRate']
    if amount > 0:
        buy_amount = amount * buy_rate
        sell_amount = amount / sell_rate
    else:
        buy_amount = sell_amount = 0.0
    
    print(f"{currency}\t\t\t{name}\t\t\t{buy_rate:.4f}\t\t\t{sell_rate:.4f}")
    if amount > 0:
        print(f"\t\t\t\t\t\t{amount:.2f} {currency} için alış: {buy_amount:.2f} {base_currency}")
        print(f"\t\t\t\t\t\t{amount:.2f} {base_currency} için satış: {sell_amount:.2f} {currency}")
    print("-"*80)

if __name__ == "__main__":
    main()



import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Döviz Kurları")
        self.setGeometry(100, 100, 800, 600)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        self.label_currency = QLabel("Döviz Kodu:")
        self.layout.addWidget(self.label_currency)
        
        self.input_currency = QLineEdit()
        self.layout.addWidget(self.input_currency)
        
        self.label_amount = QLabel("Miktar:")
        self.layout.addWidget(self.label_amount)
        
        self.input_amount = QLineEdit()
        self.layout.addWidget(self.input_amount)
        
        self.button_get_rates = QPushButton("Kurları Getir")
        self.button_get_rates.clicked.connect(self.get_exchange_rates)
        self.layout.addWidget(self.button_get_rates)
        
        self.table = QTableWidget()
        self.layout.addWidget(self.table)
        
    def get_exchange_rates(self):
        base_currency = self.input_currency.text().strip().upper()
        amount = float(self.input_amount.text().strip() or 0.0)
        
        url = f"https://www.floatrates.com/daily/{base_currency}.json"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Authorization': 'Bearer YOUR_API_KEY_HERE'  # Buraya kendi API anahtarınızı ekleyin
        }
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # HTTP hatalarını kontrol et
            
            data = response.json()
            
            self.table.clear()  # Tabloyu temizle
            
            self.table.setColumnCount(5)
            self.table.setHorizontalHeaderLabels(["Kod", "İsim", "Alış", "Satış", f"{amount:.2f} {base_currency} için Alış"])
            
            self.table.setRowCount(len(data))
            
            row = 0
            for currency, info in data.items():
                name = info['name']
                buy_rate = info['rate']
                sell_rate = info['inverseRate']
                
                buy_amount = amount * float(buy_rate)
                sell_amount = amount / float(sell_rate)
                
                self.table.setItem(row, 0, QTableWidgetItem(currency))
                self.table.setItem(row, 1, QTableWidgetItem(name))
                self.table.setItem(row, 2, QTableWidgetItem(f"{buy_rate:.4f}"))
                self.table.setItem(row, 3, QTableWidgetItem(f"{sell_rate:.4f}"))
                self.table.setItem(row, 4, QTableWidgetItem(f"{buy_amount:.2f}"))
                
                row += 1
        
        except requests.exceptions.HTTPError as err:
            print(f"Hata! HTTP isteği başarısız oldu. Hata kodu: {err.response.status_code}")
            if err.response.status_code == 403:
                print("403 Forbidden hatası: Erişim reddedildi. Lütfen API erişim anahtarınızı kontrol edin veya farklı bir API kullanmayı deneyin.")
        
        except requests.exceptions.RequestException as e:
            print(f"Hata! İstek başarısız oldu: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())



import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QHBoxLayout, QComboBox


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Döviz Kurları")
        self.setGeometry(100, 100, 800, 600)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        # Üst bölüm (Döviz seçimi ve miktar girişi)
        self.top_layout = QHBoxLayout()
        
        self.label_currency = QLabel("Döviz Kodu:")
        self.top_layout.addWidget(self.label_currency)
        
        self.input_currency = QComboBox()
        self.input_currency.addItems(["USD", "EUR", "GBP", "JPY"])  # Örnek döviz kodları
        self.top_layout.addWidget(self.input_currency)
        
        self.label_amount = QLabel("Miktar:")
        self.top_layout.addWidget(self.label_amount)
        
        self.input_amount = QLineEdit()
        self.top_layout.addWidget(self.input_amount)
        
        self.button_get_rates = QPushButton("Kurları Getir")
        self.button_get_rates.clicked.connect(self.get_exchange_rates)
        self.top_layout.addWidget(self.button_get_rates)
        
        self.layout.addLayout(self.top_layout)
        
        # Tablo
        self.table = QTableWidget()
        self.layout.addWidget(self.table)
        
    def get_exchange_rates(self):
        base_currency = self.input_currency.currentText().strip().upper()
        amount = float(self.input_amount.text().strip() or 0.0)
        
        url = f"https://www.floatrates.com/daily/{base_currency}.json"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Authorization': 'Bearer YOUR_API_KEY_HERE'  # Buraya kendi API anahtarınızı ekleyin
        }
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # HTTP hatalarını kontrol et
            
            data = response.json()
            
            self.table.clear()  # Tabloyu temizle
            
            self.table.setColumnCount(5)
            self.table.setHorizontalHeaderLabels(["Kod", "İsim", "Alış", "Satış", f"{amount:.2f} {base_currency} için Alış"])
            
            self.table.setRowCount(len(data))
            
            row = 0
            for currency, info in data.items():
                name = info['name']
                buy_rate = info['rate']
                sell_rate = info['inverseRate']
                
                buy_amount = amount * float(buy_rate)
                sell_amount = amount / float(sell_rate)
                
                self.table.setItem(row, 0, QTableWidgetItem(currency))
                self.table.setItem(row, 1, QTableWidgetItem(name))
                self.table.setItem(row, 2, QTableWidgetItem(f"{buy_rate:.4f}"))
                self.table.setItem(row, 3, QTableWidgetItem(f"{sell_rate:.4f}"))
                self.table.setItem(row, 4, QTableWidgetItem(f"{buy_amount:.2f}"))
                
                row += 1
        
        except requests.exceptions.HTTPError as err:
            print(f"Hata! HTTP isteği başarısız oldu. Hata kodu: {err.response.status_code}")
            if err.response.status_code == 403:
                print("403 Forbidden hatası: Erişim reddedildi. Lütfen API erişim anahtarınızı kontrol edin veya farklı bir API kullanmayı deneyin.")
        
        except requests.exceptions.RequestException as e:
            print(f"Hata! İstek başarısız oldu: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())




import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QHBoxLayout, QComboBox


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Döviz Kurları")
        self.setGeometry(100, 100, 1000, 600)  # Pencere boyutu genişletildi
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        # Üst bölüm (Döviz seçimi ve miktar girişi)
        self.top_layout = QHBoxLayout()
        
        self.label_currency = QLabel("Döviz Kodu:")
        self.top_layout.addWidget(self.label_currency)
        
        self.input_currency = QComboBox()
        self.input_currency.addItems(["USD", "EUR", "GBP", "JPY"])  # Örnek döviz kodları
        self.top_layout.addWidget(self.input_currency)
        
        self.label_amount = QLabel("Miktar:")
        self.top_layout.addWidget(self.label_amount)
        
        self.input_amount = QLineEdit()
        self.top_layout.addWidget(self.input_amount)
        
        self.button_get_rates = QPushButton("Kurları Getir")
        self.button_get_rates.clicked.connect(self.get_exchange_rates)
        self.top_layout.addWidget(self.button_get_rates)
        
        self.layout.addLayout(self.top_layout)
        
        # İlk tablo (Seçilen döviz için kurlar)
        self.table_selected_currency = QTableWidget()
        self.layout.addWidget(self.table_selected_currency)
        
        # İkinci tablo (Tüm döviz kurları)
        self.table_all_currencies = QTableWidget()
        self.layout.addWidget(self.table_all_currencies)
        
    def get_exchange_rates(self):
        base_currency = self.input_currency.currentText().strip().upper()
        amount = float(self.input_amount.text().strip() or 0.0)
        
        url_selected = f"https://www.floatrates.com/daily/{base_currency}.json"
        url_all = "https://www.floatrates.com/daily.json"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Authorization': 'Bearer YOUR_API_KEY_HERE'  # Buraya kendi API anahtarınızı ekleyin
        }
        
        try:
            # Seçilen döviz için veri al
            response_selected = requests.get(url_selected, headers=headers)
            response_selected.raise_for_status()  # HTTP hatalarını kontrol et
            data_selected = response_selected.json()
            
            self.table_selected_currency.clear()  # Tabloyu temizle
            self.table_selected_currency.setColumnCount(5)
            self.table_selected_currency.setHorizontalHeaderLabels(["Kod", "İsim", "Alış", "Satış", f"{amount:.2f} {base_currency} için Alış"])
            self.table_selected_currency.setRowCount(len(data_selected))
            
            row = 0
            for currency, info in data_selected.items():
                name = info['name']
                buy_rate = info['rate']
                sell_rate = info['inverseRate']
                
                self.table_selected_currency.setItem(row, 0, QTableWidgetItem(currency))
                self.table_selected_currency.setItem(row, 1, QTableWidgetItem(name))
                self.table_selected_currency.setItem(row, 2, QTableWidgetItem(f"{buy_rate:.4f}"))
                self.table_selected_currency.setItem(row, 3, QTableWidgetItem(f"{sell_rate:.4f}"))
                self.table_selected_currency.setItem(row, 4, QTableWidgetItem(f"{amount:.2f}"))
                
                row += 1
            
            # Tüm döviz kurları için veri al
            response_all = requests.get(url_all, headers=headers)
            response_all.raise_for_status()  # HTTP hatalarını kontrol et
            data_all = response_all.json()
            
            self.table_all_currencies.clear()  # Tabloyu temizle
            self.table_all_currencies.setColumnCount(4)
            self.table_all_currencies.setHorizontalHeaderLabels(["Kod", "İsim", "Alış", "Satış"])
            self.table_all_currencies.setRowCount(len(data_all))
            
            row = 0
            for currency, info in data_all.items():
                name = info['name']
                buy_rate = info['rate']
                sell_rate = info['inverseRate']
                
                self.table_all_currencies.setItem(row, 0, QTableWidgetItem(currency))
                self.table_all_currencies.setItem(row, 1, QTableWidgetItem(name))
                self.table_all_currencies.setItem(row, 2, QTableWidgetItem(f"{buy_rate:.4f}"))
                self.table_all_currencies.setItem(row, 3, QTableWidgetItem(f"{sell_rate:.4f}"))
                
                row += 1
        
        except requests.exceptions.HTTPError as err:
            print(f"Hata! HTTP isteği başarısız oldu. Hata kodu: {err.response.status_code}")
            if err.response.status_code == 403:
                print("403 Forbidden hatası: Erişim reddedildi. Lütfen API erişim anahtarınızı kontrol edin veya farklı bir API kullanmayı deneyin.")
        
        except requests.exceptions.RequestException as e:
            print(f"Hata! İstek başarısız oldu: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())




import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QHBoxLayout, QComboBox


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Döviz Kurları")
        self.setGeometry(100, 100, 1000, 600)  # Pencere boyutu genişletildi
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        # Üst bölüm (Döviz seçimi ve miktar girişi)
        self.top_layout = QHBoxLayout()
        
        self.label_currency = QLabel("Döviz Kodu:")
        self.top_layout.addWidget(self.label_currency)
        
        self.input_currency = QComboBox()
        self.input_currency.addItems(["USD", "EUR", "GBP", "JPY"])  # Örnek döviz kodları
        self.top_layout.addWidget(self.input_currency)
        
        self.label_amount = QLabel("Miktar:")
        self.top_layout.addWidget(self.label_amount)
        
        self.input_amount = QLineEdit()
        self.top_layout.addWidget(self.input_amount)
        
        self.button_get_rates = QPushButton("Kurları Getir")
        self.button_get_rates.clicked.connect(self.get_exchange_rates)
        self.top_layout.addWidget(self.button_get_rates)
        
        self.layout.addLayout(self.top_layout)
        
        # Tablo (Seçilen döviz için kurlar ve dönüşümler)
        self.table_exchange_rates = QTableWidget()
        self.layout.addWidget(self.table_exchange_rates)
        
    def get_exchange_rates(self):
        base_currency = self.input_currency.currentText().strip().upper()
        amount = float(self.input_amount.text().strip() or 0.0)
        
        url_selected = f"https://www.floatrates.com/daily/{base_currency}.json"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Authorization': 'Bearer YOUR_API_KEY_HERE'  # Buraya kendi API anahtarınızı ekleyin
        }
        
        try:
            # Seçilen döviz için veri al
            response_selected = requests.get(url_selected, headers=headers)
            response_selected.raise_for_status()  # HTTP hatalarını kontrol et
            data_selected = response_selected.json()
            
            self.table_exchange_rates.clear()  # Tabloyu temizle
            self.table_exchange_rates.setColumnCount(4)
            self.table_exchange_rates.setHorizontalHeaderLabels(["Döviz Kodu", "Döviz Adı", f"{amount:.2f} {base_currency} için Alış", "Eşdeğer Miktar"])
            self.table_exchange_rates.setRowCount(len(data_selected))
            
            row = 0
            for currency, info in data_selected.items():
                name = info['name']
                buy_rate = info['rate']
                
                equivalent_amount = buy_rate * amount
                
                self.table_exchange_rates.setItem(row, 0, QTableWidgetItem(currency))
                self.table_exchange_rates.setItem(row, 1, QTableWidgetItem(name))
                self.table_exchange_rates.setItem(row, 2, QTableWidgetItem(f"{buy_rate:.4f}"))
                self.table_exchange_rates.setItem(row, 3, QTableWidgetItem(f"{equivalent_amount:.2f}"))
                
                row += 1
        
        except requests.exceptions.HTTPError as err:
            print(f"Hata! HTTP isteği başarısız oldu. Hata kodu: {err.response.status_code}")
            if err.response.status_code == 403:
                print("403 Forbidden hatası: Erişim reddedildi. Lütfen API erişim anahtarınızı kontrol edin veya farklı bir API kullanmayı deneyin.")
        
        except requests.exceptions.RequestException as e:
            print(f"Hata! İstek başarısız oldu: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())



import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QHBoxLayout, QComboBox


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Döviz Kurları")
        self.setGeometry(100, 100, 1000, 600)  # Pencere boyutu genişletildi
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        # Üst bölüm (Döviz seçimi ve miktar girişi)
        self.top_layout = QHBoxLayout()
        
        self.label_currency = QLabel("Döviz Kodu:")
        self.top_layout.addWidget(self.label_currency)
        
        self.input_currency = QComboBox()
        self.input_currency.addItems(["USD", "EUR", "GBP", "JPY", "TRY"])  # Türk Lirası da eklendi
        self.top_layout.addWidget(self.input_currency)
        
        self.label_amount = QLabel("Miktar:")
        self.top_layout.addWidget(self.label_amount)
        
        self.input_amount = QLineEdit()
        self.top_layout.addWidget(self.input_amount)
        
        self.button_get_rates = QPushButton("Kurları Getir")
        self.button_get_rates.clicked.connect(self.get_exchange_rates)
        self.top_layout.addWidget(self.button_get_rates)
        
        self.layout.addLayout(self.top_layout)
        
        # Tablo (Seçilen döviz için kurlar ve dönüşümler)
        self.table_exchange_rates = QTableWidget()
        self.layout.addWidget(self.table_exchange_rates)
        
    def get_exchange_rates(self):
        base_currency = self.input_currency.currentText().strip().upper()
        amount = float(self.input_amount.text().strip() or 0.0)
        
        url_selected = f"https://www.floatrates.com/daily/{base_currency}.json"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Authorization': 'Bearer YOUR_API_KEY_HERE'  # Buraya kendi API anahtarınızı ekleyin
        }
        
        try:
            # Seçilen döviz için veri al
            response_selected = requests.get(url_selected, headers=headers)
            response_selected.raise_for_status()  # HTTP hatalarını kontrol et
            data_selected = response_selected.json()
            
            self.table_exchange_rates.clear()  # Tabloyu temizle
            self.table_exchange_rates.setColumnCount(4)
            self.table_exchange_rates.setHorizontalHeaderLabels(["Döviz Kodu", "Döviz Adı", f"{amount:.2f} {base_currency} için Alış", "Eşdeğer Miktar"])
            self.table_exchange_rates.setRowCount(len(data_selected))
            
            row = 0
            for currency, info in data_selected.items():
                name = info['name']
                buy_rate = info['rate']
                
                equivalent_amount = buy_rate * amount
                
                self.table_exchange_rates.setItem(row, 0, QTableWidgetItem(currency))
                self.table_exchange_rates.setItem(row, 1, QTableWidgetItem(name))
                self.table_exchange_rates.setItem(row, 2, QTableWidgetItem(f"{buy_rate:.4f}"))
                self.table_exchange_rates.setItem(row, 3, QTableWidgetItem(f"{equivalent_amount:.2f}"))
                
                row += 1
        
        except requests.exceptions.HTTPError as err:
            print(f"Hata! HTTP isteği başarısız oldu. Hata kodu: {err.response.status_code}")
            if err.response.status_code == 403:
                print("403 Forbidden hatası: Erişim reddedildi. Lütfen API erişim anahtarınızı kontrol edin veya farklı bir API kullanmayı deneyin.")
        
        except requests.exceptions.RequestException as e:
            print(f"Hata! İstek başarısız oldu: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())




import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QHBoxLayout, QComboBox


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Döviz Kurları")
        self.setGeometry(100, 100, 1000, 600)  # Pencere boyutu genişletildi
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        # Üst bölüm (Döviz seçimi ve miktar girişi)
        self.top_layout = QHBoxLayout()
        
        self.label_currency = QLabel("Döviz Kodu:")
        self.top_layout.addWidget(self.label_currency)
        
        self.input_currency = QComboBox()
        self.input_currency.addItems(["USD", "EUR", "GBP", "JPY"])  # Örnek döviz kodları
        self.top_layout.addWidget(self.input_currency)
        
        self.label_amount = QLabel("Miktar:")
        self.top_layout.addWidget(self.label_amount)
        
        self.input_amount = QLineEdit()
        self.input_amount.setText("0")
        self.top_layout.addWidget(self.input_amount)
        
        self.button_get_rates = QPushButton("Kurları Getir")
        self.button_get_rates.clicked.connect(self.get_exchange_rates)
        self.top_layout.addWidget(self.button_get_rates)
        
        self.layout.addLayout(self.top_layout)
        
        # Tablo
        self.table_exchange_rates = QTableWidget()
        self.layout.addWidget(self.table_exchange_rates)
        
    def get_exchange_rates(self):
        base_currency = self.input_currency.currentText().strip().upper()
        amount = float(self.input_amount.text().strip() or 0.0)
        
        url_selected = f"https://www.floatrates.com/daily/{base_currency}.json"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Authorization': 'Bearer YOUR_API_KEY_HERE'  # Buraya kendi API anahtarınızı ekleyin
        }
        
        try:
            # Seçilen döviz için veri al
            response_selected = requests.get(url_selected, headers=headers)
            response_selected.raise_for_status()  # HTTP hatalarını kontrol et
            data_selected = response_selected.json()
            
            self.table_exchange_rates.clear()  # Tabloyu temizle
            self.table_exchange_rates.setColumnCount(4)
            self.table_exchange_rates.setHorizontalHeaderLabels(["Döviz Kodu", "Döviz Adı", "Alış Kuru", "Miktarın Karşılığı"])
            self.table_exchange_rates.setRowCount(len(data_selected))
            
            row = 0
            for currency, info in data_selected.items():
                name = info['name']
                buy_rate = info['rate']
                
                equivalent_amount = buy_rate * amount
                
                self.table_exchange_rates.setItem(row, 0, QTableWidgetItem(currency))
                self.table_exchange_rates.setItem(row, 1, QTableWidgetItem(name))
                self.table_exchange_rates.setItem(row, 2, QTableWidgetItem(f"{buy_rate:.4f}"))
                self.table_exchange_rates.setItem(row, 3, QTableWidgetItem(f"{equivalent_amount:.2f}"))
                
                row += 1
        
        except requests.exceptions.HTTPError as err:
            print(f"Hata! HTTP isteği başarısız oldu. Hata kodu: {err.response.status_code}")
            if err.response.status_code == 403:
                print("403 Forbidden hatası: Erişim reddedildi. Lütfen API erişim anahtarınızı kontrol edin veya farklı bir API kullanmayı deneyin.")
        
        except requests.exceptions.RequestException as e:
            print(f"Hata! İstek başarısız oldu: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())



import sys
import requests
import xml.etree.ElementTree as ET
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QHBoxLayout, QComboBox, QFileDialog, QMessageBox


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Döviz Kurları")
        self.setGeometry(100, 100, 1000, 600)  # Pencere boyutu genişletildi
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        # Üst bölüm (Döviz seçimi ve miktar girişi)
        self.top_layout = QHBoxLayout()
        
        self.label_currency = QLabel("Döviz Kodu:")
        self.top_layout.addWidget(self.label_currency)
        
        self.input_currency = QComboBox()
        self.input_currency.addItems(["USD", "EUR", "GBP", "JPY"])  # Örnek döviz kodları
        self.top_layout.addWidget(self.input_currency)
        
        self.label_amount = QLabel("Miktar:")
        self.top_layout.addWidget(self.label_amount)
        
        self.input_amount = QLineEdit()
        self.input_amount.setText("0")
        self.top_layout.addWidget(self.input_amount)
        
        self.button_get_rates = QPushButton("Kurları Getir")
        self.button_get_rates.clicked.connect(self.get_exchange_rates)
        self.top_layout.addWidget(self.button_get_rates)
        
        # XML Olarak Kaydet butonu
        self.button_save_xml = QPushButton("XML Olarak Kaydet")
        self.button_save_xml.clicked.connect(self.save_as_xml)
        self.top_layout.addWidget(self.button_save_xml)
        
        self.layout.addLayout(self.top_layout)
        
        # Tablo
        self.table_exchange_rates = QTableWidget()
        self.layout.addWidget(self.table_exchange_rates)
        
    def get_exchange_rates(self):
        base_currency = self.input_currency.currentText().strip().upper()
        amount = float(self.input_amount.text().strip() or 0.0)
        
        url_selected = f"https://www.floatrates.com/daily/{base_currency}.json"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Authorization': 'Bearer YOUR_API_KEY_HERE'  # Buraya kendi API anahtarınızı ekleyin
        }
        
        try:
            # Seçilen döviz için veri al
            response_selected = requests.get(url_selected, headers=headers)
            response_selected.raise_for_status()  # HTTP hatalarını kontrol et
            data_selected = response_selected.json()
            
            # Tabloyu güncelle
            self.table_exchange_rates.clear()  # Tabloyu temizle
            self.table_exchange_rates.setColumnCount(4)
            self.table_exchange_rates.setHorizontalHeaderLabels(["Döviz Kodu", "Döviz Adı", "Alış Kuru", "Miktarın Karşılığı"])
            self.table_exchange_rates.setRowCount(len(data_selected))
            
            row = 0
            for currency, info in data_selected.items():
                name = info['name']
                buy_rate = info['rate']
                
                equivalent_amount = buy_rate * amount
                
                self.table_exchange_rates.setItem(row, 0, QTableWidgetItem(currency))
                self.table_exchange_rates.setItem(row, 1, QTableWidgetItem(name))
                self.table_exchange_rates.setItem(row, 2, QTableWidgetItem(f"{buy_rate:.4f}"))
                self.table_exchange_rates.setItem(row, 3, QTableWidgetItem(f"{equivalent_amount:.2f}"))
                
                row += 1
        
        except requests.exceptions.HTTPError as err:
            print(f"Hata! HTTP isteği başarısız oldu. Hata kodu: {err.response.status_code}")
            if err.response.status_code == 403:
                print("403 Forbidden hatası: Erişim reddedildi. Lütfen API erişim anahtarınızı kontrol edin veya farklı bir API kullanmayı deneyin.")
        
        except requests.exceptions.RequestException as e:
            print(f"Hata! İstek başarısız oldu: {e}")
    
    def save_as_xml(self):
        base_currency = self.input_currency.currentText().strip().upper()
        amount = float(self.input_amount.text().strip() or 0.0)
        
        url_selected = f"https://www.floatrates.com/daily/{base_currency}.json"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Authorization': 'Bearer YOUR_API_KEY_HERE'  # Buraya kendi API anahtarınızı ekleyin
        }
        
        try:
            
            response_selected = requests.get(url_selected, headers=headers)
            response_selected.raise_for_status()  
            data_selected = response_selected.json()
            
            # XML ağacı oluştur
            root = ET.Element("kurlar")
            
            for currency, info in data_selected.items():
                kur = ET.SubElement(root, "kur")
                name = ET.SubElement(kur, "name")
                name.text = info['name']
                code = ET.SubElement(kur, "code")
                code.text = currency
                rate = ET.SubElement(kur, "rate")
                rate.text = f"{info['rate']:.4f}"
            
            # XML dosyasını kaydet
            file_name, _ = QFileDialog.getSaveFileName(self, "XML Olarak Kaydet", "", "XML Files (*.xml)")
            if file_name:
                ET.ElementTree(root).write(file_name, encoding='utf-8', xml_declaration=True)
                QMessageBox.information(self, "Başarılı", "XML dosyası başarıyla kaydedildi.")
        
        except requests.exceptions.HTTPError as err:
            print(f"Hata! HTTP isteği başarısız oldu. Hata kodu: {err.response.status_code}")
            if err.response.status_code == 403:
                print("403 Forbidden hatası: Erişim reddedildi. Lütfen API erişim anahtarınızı kontrol edin veya farklı bir API kullanmayı deneyin.")
        
        except requests.exceptions.RequestException as e:
            print(f"Hata! İstek başarısız oldu: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QHBoxLayout, QComboBox, QFileDialog, QMessageBox
import xml.etree.ElementTree as ET


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Döviz Kurları")
        self.setGeometry(100, 100, 1000, 600)  # Pencere boyutu genişletildi
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        # Üst bölüm (Döviz seçimi ve miktar girişi)
        self.top_layout = QHBoxLayout()
        
        self.label_currency = QLabel("Döviz Kodu:")
        self.top_layout.addWidget(self.label_currency)
        
        self.input_currency = QComboBox()
        self.input_currency.addItems(["USD", "EUR", "GBP", "JPY"])  # Örnek döviz kodları
        self.top_layout.addWidget(self.input_currency)
        
        self.label_amount = QLabel("Miktar:")
        self.top_layout.addWidget(self.label_amount)
        
        self.input_amount = QLineEdit()
        self.input_amount.setText("0")
        self.top_layout.addWidget(self.input_amount)
        
        self.button_get_rates = QPushButton("Kurları Getir")
        self.button_get_rates.clicked.connect(self.get_exchange_rates)
        self.top_layout.addWidget(self.button_get_rates)
        
        # XML Olarak Kaydet butonu
        self.button_save_xml = QPushButton("XML Olarak Kaydet")
        self.button_save_xml.clicked.connect(self.save_as_xml)
        self.top_layout.addWidget(self.button_save_xml)
        
        self.layout.addLayout(self.top_layout)
        
        # Tablo
        self.table_exchange_rates = QTableWidget()
        self.layout.addWidget(self.table_exchange_rates)
        
    def get_exchange_rates(self):
        base_currency = self.input_currency.currentText().strip().upper()
        amount = float(self.input_amount.text().strip() or 0.0)
        
        url_selected = f"https://www.floatrates.com/daily/{base_currency}.json"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Authorization': 'Bearer YOUR_API_KEY_HERE'  # Buraya kendi API anahtarınızı ekleyin
        }
        
        try:
            # Seçilen döviz için veri al
            response_selected = requests.get(url_selected, headers=headers)
            response_selected.raise_for_status()  # HTTP hatalarını kontrol et
            data_selected = response_selected.json()
            
            # Tabloyu güncelle
            self.table_exchange_rates.clear()  # Tabloyu temizle
            self.table_exchange_rates.setColumnCount(4)
            self.table_exchange_rates.setHorizontalHeaderLabels(["Döviz Kodu", "Döviz Adı", "Alış Kuru", "Miktarın Karşılığı"])
            self.table_exchange_rates.setRowCount(len(data_selected))
            
            row = 0
            for currency, info in data_selected.items():
                name = info['name']
                buy_rate = info['rate']
                
                equivalent_amount = buy_rate * amount
                
                self.table_exchange_rates.setItem(row, 0, QTableWidgetItem(currency))
                self.table_exchange_rates.setItem(row, 1, QTableWidgetItem(name))
                self.table_exchange_rates.setItem(row, 2, QTableWidgetItem(f"{buy_rate:.4f}"))
                self.table_exchange_rates.setItem(row, 3, QTableWidgetItem(f"{equivalent_amount:.2f}"))
                
                row += 1
        
        except requests.exceptions.HTTPError as err:
            print(f"Hata! HTTP isteği başarısız oldu. Hata kodu: {err.response.status_code}")
            if err.response.status_code == 403:
                print("403 Forbidden hatası: Erişim reddedildi. Lütfen API erişim anahtarınızı kontrol edin veya farklı bir API kullanmayı deneyin.")
        
        except requests.exceptions.RequestException as e:
            print(f"Hata! İstek başarısız oldu: {e}")
    
    def save_as_xml(self):
        base_currency = self.input_currency.currentText().strip().upper()
        amount = float(self.input_amount.text().strip() or 0.0)
        
        url_selected = f"https://www.floatrates.com/daily/{base_currency}.json"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Authorization': 'Bearer YOUR_API_KEY_HERE'  # apı anahtarı
        }
        
        try:
            
            response_selected = requests.get(url_selected, headers=headers)
            response_selected.raise_for_status()  # HTTP hataları burda
            data_selected = response_selected.json()
            
            
            root = ET.Element("kurlar")
            
            for currency, info in data_selected.items():
                kur = ET.SubElement(root, "kur")
                name = ET.SubElement(kur, "name")
                name.text = info['name']
                code = ET.SubElement(kur, "code")
                code.text = currency
                rate = ET.SubElement(kur, "rate")
                rate.text = f"{info['rate']:.4f}"
            
            
            file_name, _ = QFileDialog.getSaveFileName(self, "XML Olarak Kaydet", "", "XML Files (*.xml)")
            if file_name:
                
                xml_str = ET.tostring(root, encoding='utf-8')
                with open(file_name, 'wb') as f:
                    f.write(xml_str)
                
                QMessageBox.information(self, "Başarılı", "XML dosyası başarıyla kaydedildi.")
        
        except requests.exceptions.HTTPError as err:
            print(f"Hata! HTTP isteği başarısız oldu. Hata kodu: {err.response.status_code}")
            if err.response.status_code == 403:
                print("403 Forbidden hatası: Erişim reddedildi. Lütfen API erişim anahtarınızı kontrol edin veya farklı bir API kullanmayı deneyin.")
        
        except requests.exceptions.RequestException as e:
            print(f"Hata! İstek başarısız oldu: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())





import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QHBoxLayout, QComboBox, QFileDialog, QMessageBox
import xml.etree.ElementTree as ET

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Döviz Kurları")
        self.setGeometry(100, 100, 1000, 600)  # Pencere boyutu genişletildi
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        # Üst bölüm (Döviz seçimi ve miktar girişi)
        self.top_layout = QHBoxLayout()
        
        self.label_currency = QLabel("Döviz Kodu:")
        self.top_layout.addWidget(self.label_currency)
        
        self.input_currency = QComboBox()
        self.input_currency.addItems(["USD", "EUR", "GBP", "JPY"])  # Örnek döviz kodları
        self.top_layout.addWidget(self.input_currency)
        
        self.label_amount = QLabel("Miktar:")
        self.top_layout.addWidget(self.label_amount)
        
        self.input_amount = QLineEdit()
        self.input_amount.setText("0")
        self.top_layout.addWidget(self.input_amount)
        
        self.button_get_rates = QPushButton("Kurları Getir")
        self.button_get_rates.clicked.connect(self.get_exchange_rates)
        self.top_layout.addWidget(self.button_get_rates)
        
        self.layout.addLayout(self.top_layout)
        
        # Tablolar için widget
        self.tables_widget = QWidget()
        self.tables_layout = QVBoxLayout()
        self.tables_widget.setLayout(self.tables_layout)
        
        # İlk tablo (API'den gelen veriler)
        self.table_exchange_rates_api = QTableWidget()
        self.tables_layout.addWidget(self.table_exchange_rates_api)
        
        # İkinci tablo (XML'den okunan veriler)
        self.table_exchange_rates_xml = QTableWidget()
        self.tables_layout.addWidget(self.table_exchange_rates_xml)
        
        self.layout.addWidget(self.tables_widget)
        
        # XML Dosyasından Oku butonu
        self.button_load_xml = QPushButton("XML Dosyasından Oku")
        self.button_load_xml.clicked.connect(self.load_from_xml)
        self.layout.addWidget(self.button_load_xml)
        
        # XML Olarak Kaydet butonu
        self.button_save_xml = QPushButton("XML Olarak Kaydet")
        self.button_save_xml.clicked.connect(self.save_as_xml)
        self.layout.addWidget(self.button_save_xml)
        
        # İlk tablo başlıkları ve satır eklenmesi
        self.table_exchange_rates_api.setColumnCount(4)
        self.table_exchange_rates_api.setHorizontalHeaderLabels(["Döviz Kodu", "Döviz Adı", "Alış Kuru", "Miktarın Karşılığı"])
        
        # İkinci tablo başlıkları ve satır eklenmesi
        self.table_exchange_rates_xml.setColumnCount(4)
        self.table_exchange_rates_xml.setHorizontalHeaderLabels(["Döviz Kodu", "Döviz Adı", "Alış Kuru", "Miktarın Karşılığı"])
        
    def get_exchange_rates(self):
        base_currency = self.input_currency.currentText().strip().upper()
        amount = float(self.input_amount.text().strip() or 0.0)
        
        url_selected = f"https://www.floatrates.com/daily/{base_currency}.json"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Authorization': 'Bearer YOUR_API_KEY_HERE'  # Buraya kendi API anahtarınızı ekleyin
        }
        
        try:
            # Seçilen döviz için veri al
            response_selected = requests.get(url_selected, headers=headers)
            response_selected.raise_for_status()  # HTTP hatalarını kontrol et
            data_selected = response_selected.json()
            
            # Tabloyu güncelle (API'den gelen veriler için)
            self.update_table(data_selected, amount, self.table_exchange_rates_api)
        
        except requests.exceptions.HTTPError as err:
            print(f"Hata! HTTP isteği başarısız oldu. Hata kodu: {err.response.status_code}")
            if err.response.status_code == 403:
                print("403 Forbidden hatası: Erişim reddedildi. Lütfen API erişim anahtarınızı kontrol edin veya farklı bir API kullanmayı deneyin.")
        
        except requests.exceptions.RequestException as e:
            print(f"Hata! İstek başarısız oldu: {e}")
    
    def update_table(self, data, amount, table_widget):
        table_widget.clearContents()  # Tablonun içeriğini temizle
        table_widget.setRowCount(0)  # Satır sayısını sıfırla
        
        row = 0
        for currency, info in data.items():
            name = info['name']
            buy_rate = info['rate']
            
            equivalent_amount = buy_rate * amount
            
            table_widget.insertRow(row)
            table_widget.setItem(row, 0, QTableWidgetItem(currency))
            table_widget.setItem(row, 1, QTableWidgetItem(name))
            table_widget.setItem(row, 2, QTableWidgetItem(f"{buy_rate:.4f}"))
            table_widget.setItem(row, 3, QTableWidgetItem(f"{equivalent_amount:.2f}"))
            
            row += 1
    
    def load_from_xml(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "XML Dosyasından Veri Oku", "", "XML Files (*.xml)")
        if file_name:
            try:
                tree = ET.parse(file_name)
                root = tree.getroot()
                
                data = {}
                for kur in root.findall('kur'):
                    code = kur.find('code').text
                    name = kur.find('name').text
                    rate = float(kur.find('rate').text)
                    
                    data[code] = {
                        'name': name,
                        'rate': rate
                    }
                
                # Tabloyu güncelle (XML'den okunan veriler için)
                self.update_table(data, 1.0, self.table_exchange_rates_xml)
                
                QMessageBox.information(self, "Başarılı", "XML dosyasından veri başarıyla yüklendi.")
            
            except ET.ParseError as e:
                print(f"Hata! XML dosyası okunurken bir hata oluştu: {str(e)}")
                QMessageBox.critical(self, "Hata", "XML dosyası okunurken bir hata oluştu.")
    
    def save_as_xml(self):
        base_currency = self.input_currency.currentText().strip().upper()
        amount = float(self.input_amount.text().strip() or 0.0)
        
        url_selected = f"https://www.floatrates.com/daily/{base_currency}.json"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Authorization': 'Bearer YOUR_API_KEY_HERE'  # apı anahtarı
        }
        
        try:
            response_selected = requests.get(url_selected, headers=headers)
            response_selected.raise_for_status()  # HTTP hataları burda
            data_selected = response_selected.json()
            
            root = ET.Element("kurlar")
            
            for currency, info in data_selected.items():
                kur = ET.SubElement(root, "kur")
                name = ET.SubElement(kur, "name")
                name.text = info['name']
                code = ET.SubElement(kur, "code")
                code.text = currency
                rate = ET.SubElement(kur, "rate")
                rate.text = f"{info['rate']:.4f}"
            
            file_name, _ = QFileDialog.getSaveFileName(self, "XML Olarak Kaydet", "", "XML Files (*.xml)")
            if file_name:
                xml_str = ET.tostring(root, encoding='utf-8')
                with open(file_name, 'wb') as f:
                    f.write(xml_str)
                
                QMessageBox.information(self, "Başarılı", "XML dosyası başarıyla kaydedildi.")
        
        except requests.exceptions.HTTPError as err:
            print(f"Hata! HTTP isteği başarısız oldu. Hata kodu: {err.response.status_code}")
            if err.response.status_code == 403:
                print("403 Forbidden hatası: Erişim reddedildi. Lütfen API erişim anahtarınızı kontrol edin veya farklı bir API kullanmayı deneyin.")
        
        except requests.exceptions.RequestException as e:
            print(f"Hata! İstek başarısız oldu: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


"""

git config –global user.email “armansarial@gmail.com”
git config -–global user.name “Arman SARIAL”


