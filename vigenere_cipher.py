# ============================================================
# Vigenère Cipher - Implementasi Python
# UTS Matematika Diskrit - Analisis Kriptografi
# ============================================================
# Algoritma: Vigenère Cipher
# Konsep Utama: Aritmetika Modular, Fungsi, Himpunan, Logika
# ============================================================

def generate_vigenere_table():
    """
    Membuat tabel Vigenère 26x26.
    Setiap baris i berisi alfabet yang digeser sebanyak i posisi.
    Konsep MatDis: Himpunan karakter alfabet Z_26, relasi pemetaan.
    """
    table = []
    for i in range(26):
        row = []
        for j in range(26):
            # Aritmetika modular: (i + j) mod 26
            row.append(chr((i + j) % 26 + ord('A')))
        table.append(row)
    return table


def extend_key(plaintext, key):
    """
    Memperpanjang kunci agar panjangnya sama dengan plaintext.
    Konsep MatDis: Fungsi periodik, operasi modular pada indeks.
    
    Contoh: plaintext="HELLO", key="KEY" -> "KEYKE"
    """
    extended = []
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            extended.append(key[key_index % len(key)])
            key_index += 1
        else:
            extended.append(char)
    return ''.join(extended)


def encrypt(plaintext, key):
    """
    Enkripsi Vigenère Cipher.
    
    Formula: C_i = (P_i + K_i) mod 26
    
    Dimana:
      P_i = indeks karakter plaintext ke-i dalam alfabet (A=0, B=1, ..., Z=25)
      K_i = indeks karakter kunci ke-i dalam alfabet
      C_i = indeks karakter ciphertext ke-i
    
    Konsep MatDis:
      - Logika: kondisional IF untuk filter karakter alfabet
      - Himpunan: domain Z_26 = {0, 1, 2, ..., 25}
      - Fungsi: f(P_i, K_i) = (P_i + K_i) mod 26 (fungsi dua variabel)
      - Aritmetika Modular: operasi penjumlahan dalam Z_26
    """
    # Validasi input (Logika Proposisional: IF-THEN)
    if not key.isalpha():
        raise ValueError("Kunci harus berupa huruf alfabet saja.")
    if len(key) == 0:
        raise ValueError("Kunci tidak boleh kosong.")
    
    key = key.upper()
    extended_key = extend_key(plaintext.upper(), key)
    ciphertext = []
    
    key_idx = 0
    for i, char in enumerate(plaintext.upper()):
        if char.isalpha():  # Proposisi: char ∈ Himpunan Alfabet
            # Konversi karakter ke indeks: A=0, B=1, ..., Z=25
            p = ord(char) - ord('A')        # Indeks plaintext
            k = ord(extended_key[i]) - ord('A')  # Indeks kunci
            
            # Enkripsi: C = (P + K) mod 26
            # Aritmetika modular dalam Z_26
            c = (p + k) % 26
            
            # Konversi indeks kembali ke karakter
            encrypted_char = chr(c + ord('A'))
            
            # Pertahankan huruf besar/kecil dari plaintext asli
            if plaintext[i].islower():
                encrypted_char = encrypted_char.lower()
            
            ciphertext.append(encrypted_char)
            key_idx += 1
        else:
            # Karakter non-alfabet tidak dienkripsi (identitas)
            ciphertext.append(char)
    
    return ''.join(ciphertext)


def decrypt(ciphertext, key):
    """
    Dekripsi Vigenère Cipher (Fungsi Invers dari Enkripsi).
    
    Formula: P_i = (C_i - K_i) mod 26
    
    Konsep MatDis:
      - Fungsi Invers: decrypt = encrypt^(-1)
      - Properti: decrypt(encrypt(P, K), K) = P  (bijektif)
      - Modular: pengurangan dalam Z_26 (selalu positif karena mod)
    """
    if not key.isalpha():
        raise ValueError("Kunci harus berupa huruf alfabet saja.")
    if len(key) == 0:
        raise ValueError("Kunci tidak boleh kosong.")
    
    key = key.upper()
    extended_key = extend_key(ciphertext.upper(), key)
    plaintext = []
    
    key_idx = 0
    for i, char in enumerate(ciphertext.upper()):
        if char.isalpha():  # Proposisi: char ∈ Himpunan Alfabet
            # Konversi karakter ke indeks
            c = ord(char) - ord('A')             # Indeks ciphertext
            k = ord(extended_key[i]) - ord('A')  # Indeks kunci
            
            # Dekripsi: P = (C - K) mod 26
            # Fungsi invers dari enkripsi
            p = (c - k) % 26  # Python mod selalu positif
            
            # Konversi indeks kembali ke karakter
            decrypted_char = chr(p + ord('A'))
            
            # Pertahankan huruf besar/kecil
            if ciphertext[i].islower():
                decrypted_char = decrypted_char.lower()
            
            plaintext.append(decrypted_char)
            key_idx += 1
        else:
            plaintext.append(char)
    
    return ''.join(plaintext)


def gcd(a, b):
    """
    Algoritma Euclidean untuk menghitung GCD (Greatest Common Divisor).
    
    Konsep MatDis Bab 4-5:
      - Algoritma Euclidean: gcd(a, b) = gcd(b, a mod b)
      - Terminasi: b = 0 → return a
      - Kompleksitas: O(log(min(a, b)))
    
    Relevansi: Memvalidasi bahwa panjang kunci dan panjang alfabet
    memiliki GCD tertentu yang mempengaruhi keamanan cipher.
    """
    while b != 0:
        a, b = b, a % b
    return a


def analyze_key_security(key):
    """
    Analisis keamanan kunci berdasarkan konsep matematika diskrit.
    
    Konsep:
      - Himpunan: key space = 26^len(key)
      - GCD: hubungan panjang kunci dengan periode alfabet
      - Kompleksitas: kekuatan brute-force
    """
    key_length = len(key)
    key_space = 26 ** key_length  # Ukuran ruang kunci
    gcd_value = gcd(key_length, 26)
    
    print(f"\n{'='*50}")
    print(f"  ANALISIS KEAMANAN KUNCI")
    print(f"{'='*50}")
    print(f"  Kunci           : {key}")
    print(f"  Panjang kunci   : {key_length}")
    print(f"  Ruang kunci     : 26^{key_length} = {key_space:,} kemungkinan")
    print(f"  GCD(len, 26)    : gcd({key_length}, 26) = {gcd_value}")
    
    if gcd_value == 1:
        print(f"  Status          : ✓ Aman (GCD = 1, distribusi merata)")
    else:
        print(f"  Status          : ⚠ Kurang ideal (GCD > 1, ada pola berulang)")
    
    print(f"  Brute-force     : {key_space:,} percobaan diperlukan")
    print(f"{'='*50}")


def print_vigenere_table_subset(key):
    """Menampilkan subset tabel Vigenère yang relevan dengan kunci."""
    table = generate_vigenere_table()
    unique_key_chars = sorted(set(key.upper()))
    
    print(f"\n  Subset Tabel Vigenère (baris kunci: {', '.join(unique_key_chars)}):")
    print(f"    {'':>4}", end="")
    for j in range(26):
        print(f" {chr(j + ord('A'))}", end="")
    print()
    print(f"    {'':>4}{'-'*52}")
    
    for k_char in unique_key_chars:
        k_idx = ord(k_char) - ord('A')
        print(f"  {k_char} | ", end="")
        for j in range(26):
            print(f" {table[k_idx][j]}", end="")
        print()


def demonstrate():
    """
    Demonstrasi lengkap Vigenère Cipher dengan contoh nyata.
    Menunjukkan alur: Plaintext → Key → Enkripsi → Ciphertext → Dekripsi → Plaintext
    """
    print("=" * 60)
    print("  VIGENÈRE CIPHER — DEMONSTRASI")
    print("  UTS Matematika Diskrit: Analisis Kriptografi")
    print("=" * 60)
    
    # Contoh 1: Teks sederhana
    plaintext1 = "MATEMATIKA DISKRIT"
    key1 = "KUNCI"
    
    print(f"\n  ▶ Contoh 1: Teks Huruf Besar")
    print(f"  {'─'*40}")
    print(f"  Plaintext  : {plaintext1}")
    print(f"  Kunci      : {key1}")
    
    extended1 = extend_key(plaintext1, key1)
    print(f"  Kunci ext. : {extended1}")
    
    cipher1 = encrypt(plaintext1, key1)
    print(f"  Ciphertext : {cipher1}")
    
    decrypted1 = decrypt(cipher1, key1)
    print(f"  Dekripsi   : {decrypted1}")
    print(f"  Verifikasi : {'✓ VALID' if decrypted1 == plaintext1 else '✗ GAGAL'}")
    
    # Detail langkah per karakter
    print(f"\n  Detail Enkripsi per Karakter:")
    print(f"  {'Char':<6} {'P_i':<5} {'K_i':<5} {'(P+K)%26':<10} {'C_i':<5} {'Result':<6}")
    print(f"  {'─'*40}")
    k_idx = 0
    for ch in plaintext1:
        if ch.isalpha():
            p = ord(ch) - ord('A')
            k = ord(key1[k_idx % len(key1)]) - ord('A')
            c = (p + k) % 26
            print(f"  {ch:<6} {p:<5} {k:<5} ({p}+{k})%26={c:<4} {c:<5} {chr(c + ord('A')):<6}")
            k_idx += 1
        else:
            print(f"  {repr(ch):<6} {'—':<5} {'—':<5} {'skip':<10} {'—':<5} {ch:<6}")
    
    # Contoh 2: Teks campuran huruf besar-kecil
    plaintext2 = "Hello World"
    key2 = "SECRET"
    
    print(f"\n  ▶ Contoh 2: Teks Campuran")
    print(f"  {'─'*40}")
    print(f"  Plaintext  : {plaintext2}")
    print(f"  Kunci      : {key2}")
    cipher2 = encrypt(plaintext2, key2)
    print(f"  Ciphertext : {cipher2}")
    decrypted2 = decrypt(cipher2, key2)
    print(f"  Dekripsi   : {decrypted2}")
    print(f"  Verifikasi : {'✓ VALID' if decrypted2 == plaintext2 else '✗ GAGAL'}")
    
    # Contoh 3: Teks panjang
    plaintext3 = "Kriptografi adalah ilmu menyembunyikan pesan"
    key3 = "MATDIS"
    
    print(f"\n  ▶ Contoh 3: Teks Panjang")
    print(f"  {'─'*40}")
    print(f"  Plaintext  : {plaintext3}")
    print(f"  Kunci      : {key3}")
    cipher3 = encrypt(plaintext3, key3)
    print(f"  Ciphertext : {cipher3}")
    decrypted3 = decrypt(cipher3, key3)
    print(f"  Dekripsi   : {decrypted3}")
    print(f"  Verifikasi : {'✓ VALID' if decrypted3 == plaintext3 else '✗ GAGAL'}")
    
    # Analisis keamanan
    analyze_key_security(key1)
    
    # Tabel Vigenère subset
    print_vigenere_table_subset(key1)
    
    # Properti matematis
    print(f"\n{'='*60}")
    print(f"  PROPERTI MATEMATIS VIGENÈRE CIPHER")
    print(f"{'='*60}")
    print(f"  1. Fungsi Bijektif:")
    print(f"     encrypt(decrypt(C, K), K) = C  ✓")
    print(f"     decrypt(encrypt(P, K), K) = P  ✓")
    print(f"  2. Aritmetika Modular:")
    print(f"     Enkripsi: C_i = (P_i + K_i) mod 26")
    print(f"     Dekripsi: P_i = (C_i - K_i) mod 26")
    print(f"  3. Himpunan Alfabet:")
    print(f"     Z_26 = {{0, 1, 2, ..., 25}}")
    print(f"     |Z_26| = 26 (kardinasi)")
    print(f"  4. GCD Relevansi:")
    print(f"     Kasiski Test: cari pola berulang di ciphertext")
    print(f"     GCD dari jarak pola → estimasi panjang kunci")
    print(f"{'='*60}")


# === MAIN PROGRAM ===
if __name__ == "__main__":
    demonstrate()
    
    # Mode interaktif
    print("\n" + "=" * 60)
    print("  MODE INTERAKTIF")
    print("=" * 60)
    
    while True:
        print("\n  Pilih operasi:")
        print("  1. Enkripsi")
        print("  2. Dekripsi")
        print("  3. Analisis Keamanan Kunci")
        print("  4. Keluar")
        
        choice = input("\n  Pilihan (1/2/3/4): ").strip()
        
        if choice == '1':
            pt = input("  Masukkan plaintext : ")
            k = input("  Masukkan kunci     : ")
            try:
                ct = encrypt(pt, k)
                print(f"  Ciphertext         : {ct}")
            except ValueError as e:
                print(f"  Error: {e}")
        
        elif choice == '2':
            ct = input("  Masukkan ciphertext: ")
            k = input("  Masukkan kunci     : ")
            try:
                pt = decrypt(ct, k)
                print(f"  Plaintext          : {pt}")
            except ValueError as e:
                print(f"  Error: {e}")
        
        elif choice == '3':
            k = input("  Masukkan kunci     : ")
            if k.isalpha():
                analyze_key_security(k)
            else:
                print("  Error: Kunci harus berupa huruf.")
        
        elif choice == '4':
            print("\n  Terima kasih! Selamat belajar Matematika Diskrit. 🔐")
            break
        
        else:
            print("  Pilihan tidak valid.")
