import os
import time
import hashlib
from PIL import Image
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher

print("=== ADIM 02: ECB ve CTR İLE GÖRÜNTÜ ŞİFRELEME ===")
# 256x256 boyutunda ortasında siyah kare olan bir test görüntüsü oluşturalım
img = Image.new("RGB", (256, 256), color=(255, 255, 255))
for x in range(64, 192):
    for y in range(64, 192):
        img.putpixel((x, y), (0, 0, 0))

raw_bytes = img.tobytes()

# ECB için 16 baytlık blok padding
pad_len = (16 - (len(raw_bytes) % 16)) % 16
padded_bytes = raw_bytes + b"\x00" * pad_len

key = os.urandom(16)
nonce = os.urandom(16)

# ECB Şifreleme
cipher_ecb = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
encryptor_ecb = cipher_ecb.encryptor()
ecb_encrypted = encryptor_ecb.update(padded_bytes) + encryptor_ecb.finalize()
ecb_bytes = ecb_encrypted[:len(raw_bytes)]

# CTR Şifreleme
cipher_ctr = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
encryptor_ctr = cipher_ctr.encryptor()
ctr_bytes = encryptor_ctr.update(raw_bytes) + encryptor_ctr.finalize()

# Görselleri üret
img_ecb = Image.frombytes("RGB", img.size, ecb_bytes)
img_ctr = Image.frombytes("RGB", img.size, ctr_bytes)

# Görselleri yan yana göster ve kaydet
fig, axes = plt.subplots(1, 3, figsize=(12, 4))
axes[0].imshow(img)
axes[0].set_title("Orijinal Görüntü")
axes[1].imshow(img_ecb)
axes[1].set_title("AES-ECB (Desen Korunur)")
axes[2].imshow(img_ctr)
axes[2].set_title("AES-CTR (Tam Gürültü)")
for ax in axes:
    ax.axis("off")
plt.tight_layout()
plt.savefig("adim2_karsilastirma.png")
print("Görüntü penceresi açıldı (kapatınca Adım 3'e geçecek)...")
plt.show()


print("\n=== ADIM 03: CTR BİT-FLIPPING vs AES-GCM DOĞRULAMA ===")
plain_text = b"Tutar: 100 TL"

# 1. CTR Modunda Bit Değiştirme
cipher_ctr2 = Cipher(algorithms.AES(key), modes.CTR(nonce))
encryptor2 = cipher_ctr2.encryptor()
ciphertext = bytearray(encryptor2.update(plain_text) + encryptor2.finalize())

target_idx = plain_text.index(b"1")
xor_diff = ord('1') ^ ord('9')
ciphertext[target_idx] ^= xor_diff

decryptor2 = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
tampered_plain = decryptor2.update(bytes(ciphertext)) + decryptor2.finalize()
print(f"CTR Orijinal Metin   : {plain_text.decode()}")
print(f"CTR Manipüle Sonuç   : {tampered_plain.decode(errors='ignore')}")

# 2. AES-GCM Modunda Deneme
aesgcm = AESGCM(key)
nonce_gcm = os.urandom(12)
gcm_ciphertext = bytearray(aesgcm.encrypt(nonce_gcm, plain_text, None))
gcm_ciphertext[target_idx] ^= xor_diff

try:
    aesgcm.decrypt(nonce_gcm, bytes(gcm_ciphertext), None)
    print("GCM Sonucu: Doğrulama başarılı (beklenmeyen durum)")
except Exception as e:
    print(f"GCM Sonucu: Hata yakalandı -> {type(e).__name__} (Bütünlük bozulduğu için işlem reddedildi!)")


print("\n=== ADIM 04: SHA-256 vs ARGON2ID SÜRE ÖLÇÜMÜ ===")
data = b"GuvenliParola123!"

# SHA-256
t0 = time.perf_counter()
for _ in range(1000):
    hashlib.sha256(data).hexdigest()
sha256_single = ((time.perf_counter() - t0) / 1000) * 1000

# Argon2id
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32)
t1 = time.perf_counter()
for _ in range(5):
    ph.hash("GuvenliParola123!")
argon_single = ((time.perf_counter() - t1) / 5) * 1000

print(f"SHA-256  (1 hash süresi): {sha256_single:.6f} ms")
print(f"Argon2id (1 hash süresi): {argon_single:.2f} ms")
print(f"Fark: Argon2id, SHA-256'dan yaklaşık {argon_single / sha256_single:.0f} kat daha yavaş çalıştı.")