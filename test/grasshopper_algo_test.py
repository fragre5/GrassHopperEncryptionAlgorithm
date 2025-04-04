import os
import tempfile
import unittest

from core.grasshopper_encryption import (
    BLOCK_SIZE,
    pad,
    unpad,
    generate_sboxes,
    generate_round_keys,
    encrypt_block,
    decrypt_block,
)
from utils.file_encryption_handler import FileEncryptionHandler


class TestEncryptionModule(unittest.TestCase):
    def setUp(self):
        self.master_key = b"01234567ABCDEFGH"
        self.plaintext = "Пример текста для тестирования шифрования."
        self.plaintext_bytes = self.plaintext.encode("utf-8")

    def test_pad_unpad(self):
        padded = pad(self.plaintext_bytes)
        self.assertEqual(len(padded) % BLOCK_SIZE, 0, "Длина должна быть кратна размеру блока")
        unpadded = unpad(padded)
        self.assertEqual(unpadded, self.plaintext_bytes, "Оригинальные данные должны восстановиться")

    def test_block_encryption_decryption(self):
        padded = pad(self.plaintext_bytes)
        block = padded[:BLOCK_SIZE]
        s_box, inv_s_box = generate_sboxes(self.master_key)
        round_keys = generate_round_keys(self.master_key, s_box)
        encrypted_block = encrypt_block(block, round_keys, s_box)
        decrypted_block = decrypt_block(encrypted_block, round_keys, inv_s_box)
        self.assertEqual(decrypted_block, block, "Шифрование/дешифрование блока должно вернуть исходные данные")

    def test_full_message_encryption_decryption(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_file = os.path.join(temp_dir, "input.txt")
            encrypted_file = os.path.join(temp_dir, "encrypted.bin")
            decrypted_file = os.path.join(temp_dir, "decrypted.txt")

            with open(input_file, "w", encoding="utf-8") as f:
                f.write(self.plaintext)

            handler = FileEncryptionHandler(self.master_key)
            handler.process_file_encryption(input_file, encrypted_file, decrypted_file)

            with open(decrypted_file, "r", encoding="utf-8") as f:
                decrypted_text = f.read()

            self.assertEqual(decrypted_text, self.plaintext, "Дешифрованный текст должен совпадать с оригиналом")

            metadata_path = os.path.join(os.getcwd(), "resources", "metadata.txt")
            self.assertTrue(os.path.exists(metadata_path), "Файл metadata.txt должен быть создан")


if __name__ == '__main__':
    unittest.main()
