import os
from core.grasshopper_encryption import (
    BLOCK_SIZE,
    pad,
    unpad,
    generate_sboxes,
    generate_round_keys,
    encrypt_block,
    decrypt_block,
)

class FileEncryptionHandler:
    """
    Класс для обработки файлов: чтение исходного текста, запись зашифрованного/дешифрованного текста,
    а также сохранение метаданных.
    """
    def __init__(self, master_key: bytes):
        self.master_key = master_key

    def read_input_file(self, input_path: str) -> bytes:
        """Читает исходный текст из файла и возвращает его в виде байтов."""
        with open(input_path, 'r', encoding='utf-8') as f:
            plaintext = f.read()
        return plaintext.encode('utf-8')

    def write_output_file(self, path: str, data: bytes, mode: str = 'wb'):
        """Записывает данные в файл по указанному пути."""
        with open(path, mode) as f:
            f.write(data)

    def write_metadata(self, metadata: str, path: str = "resources/metadata.txt"):
        """Сохраняет метаданные (S-блоки и раундовые ключи) в текстовый файл."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(metadata)

    def process_file_encryption(self, input_path: str, encrypted_path: str, decrypted_path: str):
        """
        Читает исходный текст из input_path, шифрует его, записывает зашифрованное сообщение
        в encrypted_path, затем дешифрует для проверки корректности и записывает результат в decrypted_path.
        Также сохраняет сгенерированные S-блоки и раундовые ключи.
        """
        # Чтение исходного файла и дополнение до кратного размера блока
        plaintext_bytes = self.read_input_file(input_path)
        padded = pad(plaintext_bytes)

        # Генерация S-блоков (π₀ и π₁) на основе мастер-ключа
        s_box, inv_s_box = generate_sboxes(self.master_key)

        # Генерация раундовых ключей
        round_keys = generate_round_keys(self.master_key, s_box)

        # Шифрование по блокам
        encrypted = b""
        for i in range(0, len(padded), BLOCK_SIZE):
            block = padded[i:i + BLOCK_SIZE]
            encrypted += encrypt_block(block, round_keys, s_box)
        self.write_output_file(encrypted_path, encrypted, mode='wb')

        # Дешифрование для проверки корректности
        decrypted = b""
        for i in range(0, len(encrypted), BLOCK_SIZE):
            block = encrypted[i:i + BLOCK_SIZE]
            decrypted += decrypt_block(block, round_keys, inv_s_box)
        decrypted = unpad(decrypted)
        decrypted_text = decrypted.decode('utf-8')
        self.write_output_file(decrypted_path, decrypted_text.encode('utf-8'), mode='wb')

        # Сохранение метаданных: S-блоки и раундовые ключи
        metadata = "S-box π0:\n" + " ".join(f"{b:02X}" for b in s_box) + "\n\n"
        metadata += "S-box π1 (обратный):\n" + " ".join(f"{b:02X}" for b in inv_s_box) + "\n\n"
        metadata += "Раундовые ключи:\n"
        for i, key in enumerate(round_keys, start=1):
            metadata += f"Key {i}: {key.hex().upper()}\n"
        self.write_metadata(metadata)

        print("Шифрование и дешифрование завершены.")
        print(f"Зашифрованный файл: {os.path.abspath(encrypted_path)}")
        print(f"Дешифрованный файл: {os.path.abspath(decrypted_path)}")
        print("Метаданные сохранены в metadata.txt")
