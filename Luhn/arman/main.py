"""
import tkinter as tk

class KrediKartAnaliziApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Kredi Kartı Analizi")
        self.geometry("400x300")

        self.label_mesaj = tk.Label(self, text="Kart numaranızı giriniz:")
        self.label_mesaj.pack()

        self.entry_kart_no = tk.Entry(self)
        self.entry_kart_no.pack()

        self.button_analiz = tk.Button(self, text="Analiz Et", command=self.kart_analiz)
        self.button_analiz.pack()

        self.label_sonuc = tk.Label(self, text="")
        self.label_sonuc.pack()

    def kart_analiz(self):
        try:
            kart_no = self.entry_kart_no.get().replace("-", "")

            if len(kart_no) != 16:
                self.label_sonuc.config(text="Kart numarası eksik!")
                return

            kart = list(map(int, kart_no))

            cift = []
            for i in range(0, 16):
                if i % 2 == 0:
                    cift.append(2 * kart[i])
                else:
                    cift.append(kart[i])

            tam = "".join(map(str, cift))
            toplam = sum(int(digit) for digit in tam)

            if toplam % 10 == 0:
                kart_turu = self.kart_turu(kart[0])
                hesap_no = "".join(map(str, kart[6:15]))
                self.label_sonuc.config(text=f"Kartınız Geçerli :)\nKart Türü: {kart_turu}\nHesap No: {hesap_no}")
            else:
                self.label_sonuc.config(text="Geçersiz kart! :P")
                self.entry_kart_no.delete(0, tk.END)
                self.entry_kart_no.focus()

        except Exception as ex:
            tk.messagebox.showerror("Hata", str(ex))

    def kart_turu(self, ilk_karakter):
        tur = {
            1: "Havayollari",
            2: "Havayollari",
            3: "Seyahat veya eğlence karti",
            4: "Hesap karti",
            5: "Hesap karti",
            6: "Alişveriş karti",
            7: "Akaryakit karti",
            8: "Haberleşme(telekominikasyon) karti",
            9: "Uluslararasi kart"
        }
        return tur.get(ilk_karakter, "Bilinmeyen Tür")

if __name__ == "__main__":
    app = KrediKartAnaliziApp()
    app.mainloop()


import tkinter as tk
from tkinter import messagebox

class KrediKartAnaliziApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Kredi Kartı Analizi")
        self.geometry("400x300")

        self.label_mesaj = tk.Label(self, text="Kart numaranızı giriniz (örn: 1234-5678-9012-3456):")
        self.label_mesaj.pack()

        self.entry_kart_no = tk.Entry(self)
        self.entry_kart_no.pack()

        self.button_analiz = tk.Button(self, text="Analiz Et", command=self.kart_analiz)
        self.button_analiz.pack()

        self.label_sonuc = tk.Label(self, text="")
        self.label_sonuc.pack()

    def kart_analiz(self):
        try:
            kart_no = self.entry_kart_no.get().replace("-", "")

            if len(kart_no) != 16 or not kart_no.isdigit():
                messagebox.showerror("Geçersiz Kart Numarası", "Kart numarası 16 haneli olmalıdır ve sadece rakamlardan oluşmalıdır.")
                return

            kart = list(map(int, kart_no))

            cift = [2 * kart[i] if i % 2 == 0 else kart[i] for i in range(16)]
            tam = "".join(map(str, cift))
            toplam = sum(int(digit) for digit in tam)

            if toplam % 10 == 0:
                kart_turu = self.kart_turu(kart[0])
                hesap_no = "".join(map(str, kart[6:15]))
                self.label_sonuc.config(text=f"Kartınız Geçerli :)\nKart Türü: {kart_turu}\nHesap No: {hesap_no}")
            else:
                messagebox.showerror("Geçersiz Kart", "Kart numarası geçersizdir. Lütfen doğru bir kart numarası giriniz.")
                self.entry_kart_no.delete(0, tk.END)
                self.entry_kart_no.focus()

        except Exception as ex:
            messagebox.showerror("Hata", str(ex))

    def kart_turu(self, ilk_karakter):
        tur = {
            1: "Havayolları",
            2: "Havayolları",
            3: "Seyahat veya eğlence kartı",
            4: "Hesap kartı",
            5: "Hesap kartı",
            6: "Alışveriş kartı",
            7: "Akaryakıt kartı",
            8: "Haberleşme (telekomünikasyon) kartı",
            9: "Uluslararası kart"
        }
        return tur.get(ilk_karakter, "Bilinmeyen Tür")

if __name__ == "__main__":
    app = KrediKartAnaliziApp()
    app.mainloop()

import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class TextEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Metin Şifreleme Uygulaması")

        self.label_key = tk.Label(root, text="Şifreleme Anahtarı:")
        self.label_key.pack()
        self.entry_key = tk.Entry(root, show='*')
        self.entry_key.pack()

        self.label_text = tk.Label(root, text="Metin:")
        self.label_text.pack()
        self.entry_text = tk.Entry(root)
        self.entry_text.pack()

        self.label_method = tk.Label(root, text="Şifreleme Yöntemi:")
        self.label_method.pack()
        self.method_var = tk.StringVar()
        self.method_var.set("Fernet") 
        self.radio_fernet = tk.Radiobutton(root, text="Fernet", variable=self.method_var, value="Fernet")
        self.radio_fernet.pack()
        self.radio_other = tk.Radiobutton(root, text="Diğer", variable=self.method_var, value="Diğer")
        self.radio_other.pack()

      
        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt_text)
        self.encrypt_button.pack()

    def generate_key(self, password):
        password = password.encode()
        salt = b'salt_'  
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def encrypt_text(self):
        key = self.generate_key(self.entry_key.get())
        text = self.entry_text.get()

        if self.method_var.get() == "Fernet":
            fernet = Fernet(key)
            encrypted_text = fernet.encrypt(text.encode())
            messagebox.showinfo("Şifrelenmiş Metin", encrypted_text.decode())
        elif self.method_var.get() == "Diğer":
            messagebox.showinfo("Hata", "Diğer şifreleme yöntemleri desteklenmemektedir.")


if __name__ == "__main__":
    root = tk.Tk()
    app = TextEncryptionApp(root)
    root.mainloop()

import tkinter as tk
from tkinter import messagebox, Text
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

class TextEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Metin Şifreleme Uygulaması")

        self.label_key = tk.Label(root, text="Şifreleme Anahtarı:")
        self.label_key.pack()
        self.entry_key = tk.Entry(root, show='*')
        self.entry_key.pack()

        self.label_text = tk.Label(root, text="Metin:")
        self.label_text.pack()
        self.entry_text = tk.Entry(root)
        self.entry_text.pack()

        self.label_method = tk.Label(root, text="Şifreleme Yöntemi:")
        self.label_method.pack()
        self.method_var = tk.StringVar()
        self.method_var.set("Fernet") 
        self.radio_fernet = tk.Radiobutton(root, text="Fernet", variable=self.method_var, value="Fernet")
        self.radio_fernet.pack()
        self.radio_other = tk.Radiobutton(root, text="Diğer", variable=self.method_var, value="Diğer")
        self.radio_other.pack()

        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt_text)
        self.encrypt_button.pack()

    def generate_key(self, password):
        password = password.encode()
        salt = b'salt_'  
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def encrypt_text(self):
        key = self.generate_key(self.entry_key.get())
        text = self.entry_text.get()

        if self.method_var.get() == "Fernet":
            fernet = Fernet(key)
            encrypted_text = fernet.encrypt(text.encode())
            self.show_encrypted_text(encrypted_text)
        elif self.method_var.get() == "Diğer":
            try:
                iv = os.urandom(16)  # Initialization vector for AES
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
                self.show_encrypted_text(encrypted_text)
            except Exception as e:
                messagebox.showerror("Hata", f"Şifreleme sırasında bir hata oluştu: {str(e)}")

    def show_encrypted_text(self, encrypted_text):
        top = tk.Toplevel(self.root)
        top.title("Şifrelenmiş Metin")

        text_box = Text(top, wrap=tk.WORD, height=10, width=40)
        text_box.insert(tk.END, base64.b64encode(encrypted_text).decode())
        text_box.pack()

if __name__ == "__main__":
    root = tk.Tk()
    app = TextEncryptionApp(root)
    root.mainloop()


import tkinter as tk
from tkinter import messagebox, Text
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

class TextEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Metin Şifreleme Uygulaması")

        self.label_key = tk.Label(root, text="Şifreleme Anahtarı:")
        self.label_key.pack()
        self.entry_key = tk.Entry(root, show='*')
        self.entry_key.pack()

        self.label_text = tk.Label(root, text="Metin:")
        self.label_text.pack()
        self.entry_text = tk.Entry(root)
        self.entry_text.pack()

        self.label_method = tk.Label(root, text="Şifreleme Yöntemi:")
        self.label_method.pack()
        self.method_var = tk.StringVar()
        self.method_var.set("Fernet")
        self.radio_fernet = tk.Radiobutton(root, text="Fernet", variable=self.method_var, value="Fernet")
        self.radio_fernet.pack()
        self.radio_chacha20 = tk.Radiobutton(root, text="ChaCha20", variable=self.method_var, value="ChaCha20")
        self.radio_chacha20.pack()

        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt_text)
        self.encrypt_button.pack()

    def generate_key(self, password, method):
        password = password.encode()
        salt = b'salt_'
        if method == "Fernet":
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
        elif method == "ChaCha20":
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def encrypt_text(self):
        key = self.generate_key(self.entry_key.get(), self.method_var.get())
        text = self.entry_text.get()

        if self.method_var.get() == "Fernet":
            try:
                fernet = Fernet(key)
                encrypted_text = fernet.encrypt(text.encode())
                messagebox.showinfo("Şifrelenmiş Metin", encrypted_text.decode())
            except Exception as e:
                messagebox.showerror("Hata", f"Şifreleme sırasında bir hata oluştu: {str(e)}")

        elif self.method_var.get() == "ChaCha20":
            try:
                iv = os.urandom(16)  # Initialization vector for ChaCha20
                cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
                messagebox.showinfo("Şifrelenmiş Metin", base64.b64encode(iv + encrypted_text).decode())
            except Exception as e:
                messagebox.showerror("Hata", f"Şifreleme sırasında bir hata oluştu: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = TextEncryptionApp(root)
    root.mainloop()

import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

class TextEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Metin Şifreleme Uygulaması")

        self.label_key = tk.Label(root, text="Şifreleme Anahtarı:")
        self.label_key.pack()
        self.entry_key = tk.Entry(root, show='*')
        self.entry_key.pack()

        self.label_text = tk.Label(root, text="Metin:")
        self.label_text.pack()
        self.entry_text = tk.Entry(root)
        self.entry_text.pack()

        self.label_method = tk.Label(root, text="Şifreleme Yöntemi:")
        self.label_method.pack()
        self.method_var = tk.StringVar()
        self.method_var.set("Fernet")
        self.radio_fernet = tk.Radiobutton(root, text="Fernet", variable=self.method_var, value="Fernet")
        self.radio_fernet.pack()
        self.radio_chacha20 = tk.Radiobutton(root, text="ChaCha20", variable=self.method_var, value="ChaCha20")
        self.radio_chacha20.pack()

        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt_text)
        self.encrypt_button.pack()

        self.new_key_button = tk.Button(root, text="Yeni Anahtar Oluştur", command=self.generate_new_key)
        self.new_key_button.pack()

    def generate_key(self, password, method):
        password = password.encode()
        salt = b'salt_'
        if method == "Fernet":
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
        elif method == "ChaCha20":
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def generate_new_key(self):
        try:
            # Yeni bir Fernet anahtarı oluştur
            fernet_key = Fernet.generate_key()
            self.entry_key.delete(0, tk.END)  # Mevcut anahtarı temizle
            self.entry_key.insert(0, fernet_key.decode())  # Yeni anahtarı ekle
            messagebox.showinfo("Yeni Anahtar Oluşturuldu", "Yeni Fernet anahtarı oluşturuldu.")
        except Exception as e:
            messagebox.showerror("Hata", f"Anahtar oluşturma sırasında bir hata oluştu: {str(e)}")

    def encrypt_text(self):
        try:
            key = self.generate_key(self.entry_key.get(), self.method_var.get())
            text = self.entry_text.get()

            if self.method_var.get() == "Fernet":
                fernet = Fernet(key)
                encrypted_text = fernet.encrypt(text.encode())
                messagebox.showinfo("Şifrelenmiş Metin", encrypted_text.decode())

            elif self.method_var.get() == "ChaCha20":
                iv = os.urandom(16)  # Initialization vector for ChaCha20
                cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
                messagebox.showinfo("Şifrelenmiş Metin", base64.b64encode(iv + encrypted_text).decode())

        except Exception as e:
            messagebox.showerror("Hata", f"Şifreleme sırasında bir hata oluştu: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = TextEncryptionApp(root)
    root.mainloop()

import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

class TextEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Metin Şifreleme Uygulaması")
        
        # Pencere boyutunu ayarla
        self.root.geometry("400x300")

        self.label_key = tk.Label(root, text="Şifreleme Anahtarı:")
        self.label_key.pack()
        self.entry_key = tk.Entry(root, show='*')
        self.entry_key.pack()

        self.label_text = tk.Label(root, text="Metin:")
        self.label_text.pack()
        self.entry_text = tk.Entry(root)
        self.entry_text.pack()

        self.label_method = tk.Label(root, text="Şifreleme Yöntemi:")
        self.label_method.pack()
        self.method_var = tk.StringVar()
        self.method_var.set("Fernet")
        self.radio_fernet = tk.Radiobutton(root, text="Fernet", variable=self.method_var, value="Fernet")
        self.radio_fernet.pack()
        self.radio_chacha20 = tk.Radiobutton(root, text="ChaCha20", variable=self.method_var, value="ChaCha20")
        self.radio_chacha20.pack()

        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt_text)
        self.encrypt_button.pack()

        self.new_key_button = tk.Button(root, text="Yeni Anahtar Oluştur", command=self.generate_new_key)
        self.new_key_button.pack()

    def generate_key(self, password, method):
        password = password.encode()
        salt = b'salt_'
        if method == "Fernet":
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
        elif method == "ChaCha20":
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def generate_new_key(self):
        try:
            # Yeni bir Fernet anahtarı oluştur
            fernet_key = Fernet.generate_key()
            self.entry_key.delete(0, tk.END)  # Mevcut anahtarı temizle
            self.entry_key.insert(0, fernet_key.decode())  # Yeni anahtarı ekle
            messagebox.showinfo("Yeni Anahtar Oluşturuldu", "Yeni Fernet anahtarı oluşturuldu.")
        except Exception as e:
            messagebox.showerror("Hata", f"Anahtar oluşturma sırasında bir hata oluştu: {str(e)}")

    def encrypt_text(self):
        try:
            key = self.generate_key(self.entry_key.get(), self.method_var.get())
            text = self.entry_text.get()

            if self.method_var.get() == "Fernet":
                fernet = Fernet(key)
                encrypted_text = fernet.encrypt(text.encode())
                messagebox.showinfo("Şifrelenmiş Metin", encrypted_text.decode())

            elif self.method_var.get() == "ChaCha20":
                iv = os.urandom(16)  # Initialization vector for ChaCha20
                cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
                messagebox.showinfo("Şifrelenmiş Metin", base64.b64encode(iv + encrypted_text).decode())

        except Exception as e:
            messagebox.showerror("Hata", f"Şifreleme sırasında bir hata oluştu: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = TextEncryptionApp(root)
    root.mainloop()

import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

class MetinSifrelemeUygulamasi:
    def __init__(self, root):
        self.root = root
        self.root.title("Metin Şifreleme Uygulaması")
        
        
        self.root.geometry("400x300")

        self.label_key = tk.Label(root, text="Şifreleme Anahtarı:")
        self.label_key.pack()
        self.entry_key = tk.Entry(root, show='*')
        self.entry_key.pack()

        self.label_text = tk.Label(root, text="Metin:")
        self.label_text.pack()
        self.entry_text = tk.Entry(root)
        self.entry_text.pack()

        self.label_method = tk.Label(root, text="Şifreleme Yöntemi:")
        self.label_method.pack()
        self.method_var = tk.StringVar()
        self.method_var.set("Fernet")
        self.radio_fernet = tk.Radiobutton(root, text="Fernet", variable=self.method_var, value="Fernet")
        self.radio_fernet.pack()
        self.radio_chacha20 = tk.Radiobutton(root, text="ChaCha20", variable=self.method_var, value="ChaCha20")
        self.radio_chacha20.pack()

        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt_text)
        self.encrypt_button.pack()

        self.new_key_button = tk.Button(root, text="Yeni Anahtar Oluştur", command=self.generate_new_key)
        self.new_key_button.pack()

    def generate_key(self, password, method):
        password = password.encode()
        salt = b'salt_'
        if method == "Fernet":
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
        elif method == "ChaCha20":
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def generate_new_key(self):
        try:
            
            fernet_key = Fernet.generate_key()
            self.entry_key.delete(0, tk.END)  # 
            self.entry_key.insert(0, fernet_key.decode())  
            messagebox.showinfo("Yeni Anahtar Oluşturuldu", "Yeni Fernet anahtarı oluşturuldu.")
        except Exception as e:
            messagebox.showerror("Hata", f"Anahtar oluşturma sırasında bir hata oluştu: {str(e)}")

    def encrypt_text(self):
        try:
            key = self.generate_key(self.entry_key.get(), self.method_var.get())
            text = self.entry_text.get()

            if self.method_var.get() == "Fernet":
                fernet = Fernet(key)
                encrypted_text = fernet.encrypt(text.encode())
                self.show_encrypted_message(encrypted_text)

            elif self.method_var.get() == "ChaCha20":
                iv = os.urandom(16)  
                cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
                self.show_encrypted_message(base64.b64encode(iv + encrypted_text).decode())

        except Exception as e:
            messagebox.showerror("Hata", f"Şifreleme sırasında bir hata oluştu: {str(e)}")

    def show_encrypted_message(self, encrypted_text):
        
        message = messagebox.showinfo("Şifrelenmiş Metin", encrypted_text)
        copy_button = tk.Button(self.root, text="Metni Kopyala", command=lambda: self.copy_to_clipboard(encrypted_text))
        copy_button.pack()

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()  

if __name__ == "__main__":
    root = tk.Tk()
    app = MetinSifrelemeUygulamasi(root)
    root.mainloop()

import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

class MetinSifrelemeUygulamasi:
    def __init__(self, root):
        self.root = root
        self.root.title("Metin Şifreleme Uygulaması")
        
        
        self.root.geometry("500x500")

        self.label_key = tk.Label(root, text="Şifreleme Anahtarı:")
        self.label_key.pack()
        self.entry_key = tk.Entry(root, show='*')
        self.entry_key.pack()

        self.label_text = tk.Label(root, text="Metin:")
        self.label_text.pack()
        self.entry_text = tk.Text(root, height=5, width=50)
        self.entry_text.pack()

        self.label_method = tk.Label(root, text="Şifreleme Yöntemi:")
        self.label_method.pack()
        self.method_var = tk.StringVar()
        self.method_var.set("Fernet")
        self.radio_fernet = tk.Radiobutton(root, text="Fernet", variable=self.method_var, value="Fernet")
        self.radio_fernet.pack()
        self.radio_chacha20 = tk.Radiobutton(root, text="ChaCha20", variable=self.method_var, value="ChaCha20")
        self.radio_chacha20.pack()

        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt_text)
        self.encrypt_button.pack()

        self.new_key_button = tk.Button(root, text="Yeni Anahtar Oluştur", command=self.generate_new_key)
        self.new_key_button.pack()

        self.reencrypt_button = tk.Button(root, text="Yeniden Şifrele", command=self.reencrypt_text)
        self.reencrypt_button.pack()

        self.result_label = tk.Label(root, text="Şifrelenmiş Metin:")
        self.result_label.pack()
        self.result_text = tk.Text(root, height=5, width=50)
        self.result_text.pack()

    def generate_key(self, password, method):
        password = password.encode()
        salt = b'salt_'
        if method == "Fernet":
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
        elif method == "ChaCha20":
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def generate_new_key(self):
        try:
            # Yeni bir Fernet anahtarı oluştur
            fernet_key = Fernet.generate_key()
            self.entry_key.delete(0, tk.END)  # Mevcut anahtarı temizle
            self.entry_key.insert(0, fernet_key.decode())  # Yeni anahtarı ekle
            messagebox.showinfo("Yeni Anahtar Oluşturuldu", "Yeni Fernet anahtarı oluşturuldu.")
        except Exception as e:
            messagebox.showerror("Hata", f"Anahtar oluşturma sırasında bir hata oluştu: {str(e)}")

    def encrypt_text(self):
        try:
            key = self.generate_key(self.entry_key.get(), self.method_var.get())
            text = self.entry_text.get("1.0", tk.END)[:-1]  # Son karakter (new line) silinsin

            if self.method_var.get() == "Fernet":
                fernet = Fernet(key)
                encrypted_text = fernet.encrypt(text.encode())
                self.result_text.delete("1.0", tk.END)
                self.result_text.insert(tk.END, encrypted_text.decode())

            elif self.method_var.get() == "ChaCha20":
                iv = os.urandom(16)  # ChaCha20 için başlatma vektörü
                cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
                self.result_text.delete("1.0", tk.END)
                self.result_text.insert(tk.END, base64.b64encode(iv + encrypted_text).decode())

        except Exception as e:
            messagebox.showerror("Hata", f"Şifreleme sırasında bir hata oluştu: {str(e)}")

    def reencrypt_text(self):
        self.result_text.delete("1.0", tk.END)
        self.encrypt_text()

if __name__ == "__main__":
    root = tk.Tk()
    app = MetinSifrelemeUygulamasi(root)
    root.mainloop()





import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from argon2 import PasswordHasher

class MetinSifrelemeUygulamasi:
    def __init__(self, root):
        self.root = root
        self.root.title("Metin Şifreleme Uygulaması")
        self.root.geometry("500x500")

        # Anahtar girişi için etiket ve giriş kutusu
        self.label_key = tk.Label(root, text="Şifreleme Anahtarı:")
        self.label_key.pack()
        self.entry_key = tk.Entry(root, show='*')
        self.entry_key.pack()

        # Metin girişi için etiket ve metin alanı
        self.label_text = tk.Label(root, text="Metin:")
        self.label_text.pack()
        self.entry_text = tk.Text(root, height=5, width=50)
        self.entry_text.pack()

        # Şifreleme yöntemi için etiket ve seçenekler
        self.label_method = tk.Label(root, text="Şifreleme Yöntemi:")
        self.label_method.pack()
        self.method_var = tk.StringVar()
        self.method_var.set("Fernet")
        self.radio_fernet = tk.Radiobutton(root, text="Fernet", variable=self.method_var, value="Fernet")
        self.radio_fernet.pack()
        self.radio_chacha20 = tk.Radiobutton(root, text="ChaCha20", variable=self.method_var, value="ChaCha20")
        self.radio_chacha20.pack()
        self.radio_argon2 = tk.Radiobutton(root, text="Argon2", variable=self.method_var, value="Argon2")
        self.radio_argon2.pack()

        # Şifreleme ve anahtar oluşturma düğmeleri
        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt_text)
        self.encrypt_button.pack()
        self.new_key_button = tk.Button(root, text="Yeni Anahtar Oluştur", command=self.generate_new_key)
        self.new_key_button.pack()
        self.reencrypt_button = tk.Button(root, text="Yeniden Şifrele", command=self.reencrypt_text)
        self.reencrypt_button.pack()

        # Şifrelenmiş metin gösterimi için etiket ve metin alanı
        self.result_label = tk.Label(root, text="Şifrelenmiş Metin:")
        self.result_label.pack()
        self.result_text = tk.Text(root, height=5, width=50)
        self.result_text.pack()

    def generate_key(self, password, method):
        password = password.encode()
        salt = os.urandom(16)  # Rastgele salt oluştur
        if method == "Fernet" or method == "ChaCha20":
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
        elif method == "Argon2":
            ph = PasswordHasher()
            key = ph.hash(password)
        return key

    def generate_new_key(self):
        try:
            if self.method_var.get() == "Fernet" or self.method_var.get() == "ChaCha20":
                # Yeni bir Fernet anahtarı oluştur
                fernet_key = Fernet.generate_key()
                self.entry_key.delete(0, tk.END)  # Mevcut anahtarı temizle
                self.entry_key.insert(0, fernet_key.decode())  # Yeni anahtarı ekle
                messagebox.showinfo("Yeni Anahtar Oluşturuldu", "Yeni Fernet anahtarı oluşturuldu.")
            elif self.method_var.get() == "Argon2":
                # Yeni bir Argon2 hashi oluştur
                ph = PasswordHasher()
                password = self.entry_key.get()
                hashed_password = ph.hash(password)
                self.entry_key.delete(0, tk.END)
                self.entry_key.insert(0, hashed_password)
                messagebox.showinfo("Yeni Anahtar Oluşturuldu", "Yeni Argon2 anahtarı oluşturuldu.")
        except Exception as e:
            messagebox.showerror("Hata", f"Anahtar oluşturma sırasında bir hata oluştu: {str(e)}")

    def encrypt_text(self):
        try:
            key = self.generate_key(self.entry_key.get(), self.method_var.get())
            text = self.entry_text.get("1.0", tk.END).strip()  # Metni al ve boşlukları kaldır

            if self.method_var.get() == "Fernet":
                fernet = Fernet(key)
                encrypted_text = fernet.encrypt(text.encode())
                self.result_text.delete("1.0", tk.END)
                self.result_text.insert(tk.END, encrypted_text.decode())

            elif self.method_var.get() == "ChaCha20":
                nonce = os.urandom(16)  # ChaCha20 için rastgele nonce oluştur
                cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
                self.result_text.delete("1.0", tk.END)
                self.result_text.insert(tk.END, base64.b64encode(nonce + encrypted_text).decode())

            elif self.method_var.get() == "Argon2":
                ph = PasswordHasher()
                try:
                    ph.verify(key, self.entry_key.get())
                    messagebox.showinfo("Şifre Doğrulama", "Şifre doğrulandı.")
                except Exception as e:
                    messagebox.showerror("Hata", f"Şifre doğrulama sırasında bir hata oluştu: {str(e)}")

        except Exception as e:
            messagebox.showerror("Hata", f"Şifreleme sırasında bir hata oluştu: {str(e)}")

    def reencrypt_text(self):
        self.result_text.delete("1.0", tk.END)
        self.encrypt_text()

if __name__ == "__main__":
    root = tk.Tk()
    app = MetinSifrelemeUygulamasi(root)
    root.mainloop()


import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os

class MetinSifrelemeUygulamasi:
    def __init__(self, root):
        self.root = root
        self.root.title("Metin Şifreleme Uygulaması")
        self.root.geometry("500x500")

        # Anahtar girişi için etiket ve giriş kutusu
        self.label_key = tk.Label(root, text="Şifreleme Anahtarı:")
        self.label_key.pack()
        self.entry_key = tk.Entry(root, show='*')
        self.entry_key.pack()

        # Metin girişi için etiket ve metin alanı
        self.label_text = tk.Label(root, text="Metin:")
        self.label_text.pack()
        self.entry_text = tk.Text(root, height=5, width=50)
        self.entry_text.pack()

        # Şifreleme yöntemi için etiket ve seçenekler
        self.label_method = tk.Label(root, text="Şifreleme Yöntemi:")
        self.label_method.pack()
        self.method_var = tk.StringVar()
        self.method_var.set("Fernet")
        self.radio_fernet = tk.Radiobutton(root, text="Fernet", variable=self.method_var, value="Fernet")
        self.radio_fernet.pack()
        self.radio_chacha20 = tk.Radiobutton(root, text="ChaCha20", variable=self.method_var, value="ChaCha20")
        self.radio_chacha20.pack()
        self.radio_aes = tk.Radiobutton(root, text="AES", variable=self.method_var, value="AES")
        self.radio_aes.pack()
        self.radio_argon2 = tk.Radiobutton(root, text="argon2", variable=self.method_var, value="argon2")
        self.radio_argon2.pack()

        # Şifreleme ve anahtar oluşturma düğmeleri
        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt_text)
        self.encrypt_button.pack()
        self.new_key_button = tk.Button(root, text="Yeni Anahtar Oluştur", command=self.generate_new_key)
        self.new_key_button.pack()
        self.reencrypt_button = tk.Button(root, text="Yeniden Şifrele", command=self.reencrypt_text)
        self.reencrypt_button.pack()

        # Şifrelenmiş metin gösterimi için etiket ve metin alanı
        self.result_label = tk.Label(root, text="Şifrelenmiş Metin:")
        self.result_label.pack()
        self.result_text = tk.Text(root, height=5, width=50)
        self.result_text.pack()

    def generate_key(self, password, method):
        password = password.encode()
        salt = os.urandom(16)  # Rastgele salt oluştur

        if method == "Fernet":
            # Fernet için anahtar oluşturma
            key = base64.urlsafe_b64encode(Fernet.generate_key())

        elif method == "ChaCha20" or method == "AES":
            # ChaCha20 ve AES için anahtar türetme
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))

        elif method == "argon2":
            # argon2 ile anahtar oluşturma
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))

        return key

    def generate_new_key(self):
        try:
            # Yeni bir Fernet anahtarı oluştur
            fernet_key = Fernet.generate_key()
            self.entry_key.delete(0, tk.END)  # Mevcut anahtarı temizle
            self.entry_key.insert(0, fernet_key.decode())  # Yeni anahtarı ekle
            messagebox.showinfo("Yeni Anahtar Oluşturuldu", "Yeni Fernet anahtarı oluşturuldu.")
        except Exception as e:
            messagebox.showerror("Hata", f"Anahtar oluşturma sırasında bir hata oluştu: {str(e)}")

    def encrypt_text(self):
        try:
            key = self.generate_key(self.entry_key.get(), self.method_var.get())
            text = self.entry_text.get("1.0", tk.END).strip()  # Metni al ve boşlukları kaldır

            if self.method_var.get() == "Fernet":
                fernet = Fernet(key)
                encrypted_text = fernet.encrypt(text.encode())
                self.result_text.delete("1.0", tk.END)
                self.result_text.insert(tk.END, encrypted_text.decode())

            elif self.method_var.get() == "ChaCha20":
                iv = os.urandom(16)  # ChaCha20 için rastgele başlatma vektörü oluştur
                cipher = Cipher(algorithms.ChaCha20(key, iv), mode=modes.XChaCha20, backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
                self.result_text.delete("1.0", tk.END)
                self.result_text.insert(tk.END, base64.b64encode(iv + encrypted_text).decode())

            elif self.method_var.get() == "AES":
                iv = os.urandom(16)  # AES için rastgele başlatma vektörü oluştur
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
                self.result_text.delete("1.0", tk.END)
                self.result_text.insert(tk.END, base64.b64encode(iv + encrypted_text).decode())

            elif self.method_var.get() == "argon2":
                # argon2 ile metni hashleme
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=os.urandom(16),
                    iterations=100000,
                    backend=default_backend()
                )
                hashed_text = base64.urlsafe_b64encode(kdf.derive(text.encode()))
                self.result_text.delete("1.0", tk.END)
                self.result_text.insert(tk.END, hashed_text.decode())

        except Exception as e:
            messagebox.showerror("Hata", f"Şifreleme sirasinda bir hata oluştu: {str(e)}")

    def reencrypt_text(self):
        self.result_text.delete("1.0", tk.END)
        self.encrypt_text()

if __name__ == "__main__":
    root = tk.Tk()
    app = MetinSifrelemeUygulamasi(root)
    root.mainloop()
    
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

class MetinSifrelemeUygulamasi:
    def __init__(self, root):
        self.root = root
        self.root.title("Metin Şifreleme Uygulaması")
        self.root.geometry("500x500")

        # Anahtar girişi için etiket ve giriş kutusu
        self.label_key = tk.Label(root, text="Şifreleme Anahtarı:")
        self.label_key.pack()
        self.entry_key = tk.Entry(root, show='*')
        self.entry_key.pack()

        # Metin girişi için etiket ve metin alanı
        self.label_text = tk.Label(root, text="Metin:")
        self.label_text.pack()
        self.entry_text = tk.Text(root, height=5, width=50)
        self.entry_text.pack()

        # Şifreleme yöntemi için etiket ve seçenekler
        self.label_method = tk.Label(root, text="Şifreleme Yöntemi:")
        self.label_method.pack()
        self.method_var = tk.StringVar()
        self.method_var.set("Fernet")
        self.radio_fernet = tk.Radiobutton(root, text="Fernet", variable=self.method_var, value="Fernet")
        self.radio_fernet.pack()
        self.radio_aes = tk.Radiobutton(root, text="AES", variable=self.method_var, value="AES")
        self.radio_aes.pack()

        # Şifreleme ve anahtar oluşturma düğmeleri
        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt_text)
        self.encrypt_button.pack()
        self.new_key_button = tk.Button(root, text="Yeni Anahtar Oluştur", command=self.generate_new_key)
        self.new_key_button.pack()
        self.reencrypt_button = tk.Button(root, text="Yeniden Şifrele", command=self.reencrypt_text)
        self.reencrypt_button.pack()

        # Şifrelenmiş metin gösterimi için etiket ve metin alanı
        self.result_label = tk.Label(root, text="Şifrelenmiş Metin:")
        self.result_label.pack()
        self.result_text = tk.Text(root, height=5, width=50)
        self.result_text.pack()

    def generate_key(self, password, method):
        password = password.encode()
        salt = os.urandom(16)  # Rastgele salt oluştur

        if method == "Fernet":
            # Fernet için anahtar oluşturma
            key = base64.urlsafe_b64encode(Fernet.generate_key())

        elif method == "AES":
            # AES için anahtar türetme
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))

        return key

    def generate_new_key(self):
        try:
            if self.method_var.get() == "Fernet":
                # Yeni bir Fernet anahtarı oluştur
                fernet_key = Fernet.generate_key()
                self.entry_key.delete(0, tk.END)  # Mevcut anahtarı temizle
                self.entry_key.insert(0, fernet_key.decode())  # Yeni anahtarı ekle
                messagebox.showinfo("Yeni Anahtar Oluşturuldu", "Yeni Fernet anahtarı oluşturuldu.")
            elif self.method_var.get() == "AES":
                # AES için yeni bir anahtar oluştur
                aes_key = self.generate_key(self.entry_key.get(), "AES")
                self.entry_key.delete(0, tk.END)  # Mevcut anahtarı temizle
                self.entry_key.insert(0, aes_key.decode())  # Yeni anahtarı ekle
                messagebox.showinfo("Yeni Anahtar Oluşturuldu", "Yeni AES anahtarı oluşturuldu.")
            else:
                messagebox.showwarning("Uyarı", "Bu yöntem için anahtar oluşturma desteklenmemektedir.")
        except Exception as e:
            messagebox.showerror("Hata", f"Anahtar oluşturma sırasında bir hata oluştu: {str(e)}")

    def encrypt_text(self):
        try:
            key = self.generate_key(self.entry_key.get(), self.method_var.get())
            text = self.entry_text.get("1.0", tk.END).strip()  # Metni al ve boşlukları kaldır

            if self.method_var.get() == "Fernet":
                fernet = Fernet(key)
                encrypted_text = fernet.encrypt(text.encode())
                self.result_text.delete("1.0", tk.END)
                self.result_text.insert(tk.END, encrypted_text.decode())

            elif self.method_var.get() == "AES":
                iv = os.urandom(16)  # aes ıcın vektorel olustur
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
                self.result_text.delete("1.0", tk.END)
                self.result_text.insert(tk.END, base64.b64encode(iv + encrypted_text).decode())

        except Exception as e:
            messagebox.showerror("Hata", f"Şifreleme sırasında bir hata oluştu: {str(e)}")

    def reencrypt_text(self):
        self.result_text.delete("1.0", tk.END)
        self.encrypt_text()

if __name__ == "__main__":
    root = tk.Tk()
    app = MetinSifrelemeUygulamasi(root)
    root.mainloop()



import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64

class MetinSifrelemeUygulamasi:
    def __init__(self, root):
        self.root = root
        self.root.title("Metin Şifreleme Uygulaması")
        self.root.geometry("500x500")

        # Anahtar girişi için etiket ve giriş kutusu
        self.label_key = tk.Label(root, text="Şifreleme Anahtarı:")
        self.label_key.pack()
        self.entry_key = tk.Entry(root, show='*')
        self.entry_key.pack()

        # Metin girişi için etiket ve metin alanı
        self.label_text = tk.Label(root, text="Metin:")
        self.label_text.pack()
        self.entry_text = tk.Text(root, height=5, width=50)
        self.entry_text.pack()

        # Şifreleme düğmesi
        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt_text)
        self.encrypt_button.pack()

        # Şifrelenmiş metin gösterimi için etiket ve metin alanı
        self.result_label = tk.Label(root, text="Şifrelenmiş Metin:")
        self.result_label.pack()
        self.result_text = tk.Text(root, height=5, width=50)
        self.result_text.pack()

    def generate_key(self):
        try:
            # Yeni bir Fernet anahtarı oluştur
            fernet_key = Fernet.generate_key()
            self.entry_key.delete(0, tk.END)  # Mevcut anahtarı temizle
            self.entry_key.insert(0, fernet_key.decode())  # Yeni anahtarı ekle
            messagebox.showinfo("Yeni Anahtar Oluşturuldu", "Yeni Fernet anahtarı oluşturuldu.")
        except Exception as e:
            messagebox.showerror("Hata", f"Anahtar oluşturma sırasında bir hata oluştu: {str(e)}")

    def encrypt_text(self):
        try:
            key = self.entry_key.get().encode()
            text = self.entry_text.get("1.0", tk.END).strip()  # Metni al ve boşlukları kaldır

            fernet = Fernet(key)
            encrypted_text = fernet.encrypt(text.encode())

            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, encrypted_text.decode())

        except Exception as e:
            messagebox.showerror("Hata", f"Şifreleme sırasında bir hata oluştu: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MetinSifrelemeUygulamasi(root)
    root.mainloop()
"""





import tkinter as tk
from tkinter import ttk
import xml.etree.ElementTree as ET
from tkinter import messagebox

class MetinSifrelemeUygulamasi:
    def __init__(self, root):
        self.root = root
        self.root.title("Metin Şifreleme Uygulaması")
        self.root.geometry("800x600")

        # Anahtar girişi için etiket ve giriş kutusu
        self.label_key = tk.Label(root, text="Şifreleme Anahtarı:")
        self.label_key.pack()
        self.entry_key = tk.Entry(root, show='*')
        self.entry_key.pack()

        # Metin girişi için etiket ve metin alanı
        self.label_text = tk.Label(root, text="Metin:")
        self.label_text.pack()
        self.entry_text = tk.Text(root, height=5, width=80)
        self.entry_text.pack()

        # Şifreleme düğmesi
        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt_text)
        self.encrypt_button.pack()

        # Şifrelenmiş metin gösterimi için etiket ve metin alanı
        self.result_label = tk.Label(root, text="Şifrelenmiş Metin:")
        self.result_label.pack()
        self.result_text = tk.Text(root, height=5, width=80)
        self.result_text.pack()

        # XML verilerini göstermek için tablo (Treeview)
        self.tree = ttk.Treeview(root)
        self.tree["columns"] = ("id", "name", "value")
        self.tree.heading("#0", text="Element")
        self.tree.heading("id", text="ID")
        self.tree.heading("name", text="Name")
        self.tree.heading("value", text="Value")
        self.tree.pack()

        # XML dosyasını yükleme düğmesi
        self.load_xml_button = tk.Button(root, text="XML Dosyasını Yükle", command=self.load_xml)
        self.load_xml_button.pack()

    def load_xml(self):
        try:
            filename = tk.filedialog.askopenfilename(filetypes=[("XML files", "*.xml")])
            tree = ET.parse(filename)
            root = tree.getroot()

            self.tree.delete(*self.tree.get_children())

            # XML'deki verileri tabloya ekle
            for elem in root.iter():
                if elem.tag != root.tag:
                    self.tree.insert("", "end", text=elem.tag, values=(elem.attrib.get("id", ""), elem.tag, elem.text))

        except Exception as e:
            messagebox.showerror("Hata", f"XML yükleme sırasında bir hata oluştu: {str(e)}")

    def encrypt_text(self):
        try:
            key = self.entry_key.get().encode()
            text = self.entry_text.get("1.0", tk.END).strip()  # Metni al ve boşlukları kaldır

            fernet = Fernet(key)
            encrypted_text = fernet.encrypt(text.encode())

            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, encrypted_text.decode())

        except Exception as e:
            messagebox.showerror("Hata", f"Şifreleme sırasında bir hata oluştu: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MetinSifrelemeUygulamasi(root)
    root.mainloop()
