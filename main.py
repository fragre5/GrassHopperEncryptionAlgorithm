import os
from utils.file_encryption_handler import FileEncryptionHandler

if __name__ == '__main__':
    input_file = "resources/input.txt"
    encrypted_file = "resources/encrypted.bin"
    decrypted_file = "resources/decrypted.txt"

    master_key = b"01234567ABCDEFGH"  # 16 байт

    if not os.path.exists(input_file):
        with open(input_file, 'w', encoding='utf-8') as f:
            f.write("Это пример исходного текста для шифрования алгоритмом 'Кузнечик'.")

    file_handler = FileEncryptionHandler(master_key)
    file_handler.process_file_encryption(input_file, encrypted_file, decrypted_file)
