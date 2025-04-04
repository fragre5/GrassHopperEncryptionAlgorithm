# Grasshopper encryption algorithm
import random

BLOCK_SIZE = 8  # Размер блока в байтах для варианта 10

# --------------------- Генерация S-блоков ---------------------
def generate_sboxes(key: bytes):
    """
    Генерирует S-блок π0 как случайную перестановку чисел от 0 до 255,
    используя значение ключа в качестве seed.
    π1 – обратная перестановка к π0.
    """
    seed = int.from_bytes(key, byteorder='big')
    random.seed(seed)
    s_box = list(range(256))
    random.shuffle(s_box)
    inv_s_box = [0] * 256
    for i, v in enumerate(s_box):
        inv_s_box[v] = i
    return s_box, inv_s_box

# --------------------- Базовые операции ---------------------
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def gf_mul(a: int, b: int, poly: int = 0x11B) -> int:
    """
    Умножение в поле Галуа GF(2^8) с использованием неприводимого полинома 0x11B.
    a, b – целые числа от 0 до 255.
    """
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return result & 0xFF

# --------------------- Линейное преобразование L ---------------------
def R(state: list) -> list:
    """
    Функция R: вычисляет XOR всех байтов, затем выполняет циклический сдвиг влево
    и добавляет вычисленное значение в конец.
    state – список целых чисел (байтов).
    """
    t = 0
    for byte in state:
        t ^= byte
    return state[1:] + [t]

def R_inv(state: list) -> list:
    """
    Обратная функция R: вычисляет первый элемент исходного списка по последнему
    элементу и остальным, затем выполняет циклический сдвиг вправо.
    """
    a0 = state[-1]
    for b in state[:-1]:
        a0 ^= b
    return [a0] + state[:-1]

def L(state: list) -> list:
    """
    Функция L – N-кратное применение функции R,
    где N равен размеру блока (BLOCK_SIZE).
    """
    result = state[:]
    for _ in range(len(state)):
        result = R(result)
    return result

def L_inv(state: list) -> list:
    """
    Обратная функция L – N-кратное применение обратной функции R_inv.
    """
    result = state[:]
    for _ in range(len(state)):
        result = R_inv(result)
    return result

# --------------------- S-блок замещения ---------------------
def substitute(block: bytes, s_box: list) -> bytes:
    """Применяет S-блок замещения к каждому байту блока."""
    return bytes(s_box[b] for b in block)

# --------------------- Генерация раундовых ключей ---------------------
def generate_round_keys(master_key: bytes, s_box: list) -> list:
    """
    Генерирует 10 раундовых ключей по следующей схеме:
      - Мастер-ключ длины 16 байт делится на две половины (A и B) по 8 байт.
      - Затем в 4 циклах по 8 итераций (32 итерации) выполняется функция Фейстеля:
            F(A, C) = L( S( A XOR C ) )
        где C – константа, вычисляемая как L([iter_num]*BLOCK_SIZE).
      - После каждого цикла к текущей паре (A, B) добавляются два новых ключа.
    Итоговый список содержит 10 ключей (ключи раундов 1…10).
    """
    if len(master_key) != 2 * BLOCK_SIZE:
        raise ValueError(f"Мастер-ключ должен быть длины {2 * BLOCK_SIZE} байт.")
    A = list(master_key[:BLOCK_SIZE])
    B = list(master_key[BLOCK_SIZE:])
    round_keys = [bytes(A), bytes(B)]
    for cycle in range(4):
        for j in range(8):
            iter_num = cycle * 8 + j + 1
            const_block = [iter_num % 256] * BLOCK_SIZE
            C = L(const_block)
            X = [a ^ c for a, c in zip(A, C)]
            Y_bytes = substitute(bytes(X), s_box)
            Y = list(Y_bytes)
            F_val = L(Y)
            new_A = [f ^ b for f, b in zip(F_val, B)]
            new_B = A
            A, B = new_A, new_B
        round_keys.append(bytes(A))
        round_keys.append(bytes(B))
    return round_keys

# --------------------- Шифрование/Дешифрование блока ---------------------
def encrypt_block(block: bytes, round_keys: list, s_box: list) -> bytes:
    """
    Шифрует блок данных (длина блока должна быть BLOCK_SIZE байт) по схеме:
      9 полных раундов: XOR с ключом, S-подстановка (π₀), линейное преобразование L,
      затем финальный XOR с 10-м ключом.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("Размер блока должен быть равен BLOCK_SIZE.")
    state = block
    for i in range(9):
        state = xor_bytes(state, round_keys[i])
        state = substitute(state, s_box)
        state = bytes(L(list(state)))
    state = xor_bytes(state, round_keys[9])
    return state

def decrypt_block(block: bytes, round_keys: list, inv_s_box: list) -> bytes:
    """
    Дешифрует блок данных по схеме, обратной шифрованию:
      - Финальный XOR с 10-м ключом,
      - 9 раундов, в каждом из которых применяется обратное L, обратная S-подстановка (π₁) и XOR с ключом.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("Размер блока должен быть равен BLOCK_SIZE.")
    state = block
    state = xor_bytes(state, round_keys[9])
    for i in range(8, -1, -1):
        state = bytes(L_inv(list(state)))
        state = substitute(state, inv_s_box)
        state = xor_bytes(state, round_keys[i])
    return state

# --------------------- Дополнение (padding) ---------------------
def pad(data: bytes) -> bytes:
    """
    Дополняет данные по схеме PKCS#7 до кратности BLOCK_SIZE.
    """
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    """
    Удаляет PKCS#7 дополнение.
    """
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Неверное значение дополнения.")
    return data[:-pad_len]
