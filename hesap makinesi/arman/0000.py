# İşlem seçeneklerini ekrana yazdıralım
"""
print("Yapılacak İşlemi Seçiniz:")
print("1. Toplama")
print("2. Çıkarma")
print("3. Çarpma")
print("4. Bölme")

# Kullanıcıdan işlem seçimini isteyelim
while True:
    try:
        secim = int(input("Lütfen işlem seçeneğini (1-4) giriniz: "))
        if secim < 1 or secim > 4:
            print("Geçersiz seçenek! Lütfen 1 ile 4 arasında bir seçenek giriniz.")
        else:
            break
    except ValueError:
        print("Geçersiz giriş! Lütfen bir tam sayı giriniz.")

# İki adet sayı alalım
while True:
    try:
        sayi1 = float(input("İlk sayıyı giriniz: "))
        sayi2 = float(input("İkinci sayıyı giriniz: "))
        break
    except ValueError:
        print("Geçersiz giriş! Lütfen sayı giriniz.")

# Seçilen işleme göre işlem yapalım ve sonucu ekrana yazdıralım
if secim == 1:
    sonuc = sayi1 + sayi2
    print(f"{sayi1} + {sayi2} = {sonuc}")
elif secim == 2:
    sonuc = sayi1 - sayi2
    print(f"{sayi1} - {sayi2} = {sonuc}")
elif secim == 3:
    sonuc = sayi1 * sayi2
    print(f"{sayi1} * {sayi2} = {sonuc}")
elif secim == 4:
    if sayi2 == 0:
        print("Hata: Sıfıra bölme işlemi yapılamaz!")
    else:
        sonuc = sayi1 / sayi2
        print(f"{sayi1} / {sayi2} = {sonuc}")
else:
    print("Beklenmeyen bir hata oluştu!")


"""



