import os
import logging
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from Cryptodome.Cipher import AES
import math
import time

# Настройка логгирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Константы
KEY_SIZE_BYTES = 16
PNG_HEADER = b'\x89PNG\r\n\x1a\n'
MEMORY_DUMP_PATH = 'dump_008.DMP'
ENCRYPTED_PNG_PATH = 'encr_008'
DECRYPTED_PNG_PATH = 'decrypted_image.png'
NUM_THREADS = 4  # Количество потоков для параллельной обработки
TOTAL_KEY_ATTEMPTS = 0  # Счётчик всех попыток проверки ключа
SUCCESSFUL_KEY_ATTEMPTS = 0  # Счётчик успешных ключей

def decrypt_png_with_key(encrypted_png, decryption_key):
    try:
        cipher = AES.new(decryption_key, AES.MODE_ECB)
        return cipher.decrypt(encrypted_png)
    except ValueError as e:
        logging.error(f"Ошибка дешифрования: {str(e)}")
        return None

def calculate_shannon_entropy(data):
    """Вычисляет энтропию Шеннона для последовательности данных"""
    if not data:
        return 0

    entropy = 0
    data_length = len(data)
    for count in Counter(data).values():
        probability = count / data_length
        entropy -= probability * math.log2(probability)
    return entropy

def is_high_entropy_key(key_candidate):
    entropy_threshold = 3.5  # Эмпирически определенный порог для 128-битного ключа
    entropy = calculate_shannon_entropy(key_candidate)
    logging.debug(f"Ключ: {key_candidate.hex()}, Энтропия: {entropy}")
    return entropy > entropy_threshold

def validate_file_existence(*file_paths):
    for file_path in file_paths:
        if not os.path.exists(file_path):
            logging.error(f"Файл не найден: {file_path}")
            raise FileNotFoundError(f"Файл не найден: {file_path}")

def extract_keys_from_dump(dump_content):
    global TOTAL_KEY_ATTEMPTS, SUCCESSFUL_KEY_ATTEMPTS
    candidate_keys = Counter(dump_content[i:i + KEY_SIZE_BYTES] for i in range(len(dump_content) - KEY_SIZE_BYTES + 1))
    valid_keys = []
    for key, occurrence in candidate_keys.items():
        TOTAL_KEY_ATTEMPTS += 1  # Учитываем каждый ключ, который мы проверяем
        if occurrence == 2 and is_high_entropy_key(key):
            SUCCESSFUL_KEY_ATTEMPTS += 1  # Счётчик успешных ключей
            valid_keys.append(key)
    return valid_keys

def process_key(candidate_key, encrypted_png):
    decrypted_png = decrypt_png_with_key(encrypted_png, candidate_key)
    if decrypted_png and decrypted_png.startswith(PNG_HEADER):
        logging.info(f"Ключ найден: {candidate_key.hex()}")
        with open(DECRYPTED_PNG_PATH, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_png)
        logging.info("Файл успешно расшифрован и сохранен")
        return True
    return False

try:
    start_time = time.time()  # Начало измерения времени
    validate_file_existence(MEMORY_DUMP_PATH, ENCRYPTED_PNG_PATH)
    with open(MEMORY_DUMP_PATH, 'rb') as dump_file, open(ENCRYPTED_PNG_PATH, 'rb') as encrypted_file:
        dump_content = dump_file.read()
        encrypted_png = encrypted_file.read()

    keys = extract_keys_from_dump(dump_content)
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        future_to_key = {executor.submit(process_key, key, encrypted_png): key for key in keys}
        for future in as_completed(future_to_key):
            if future.result():
                logging.info("Процесс расшифровки завершен успешно.")
                break
        else:
            logging.info("Ключ не найден")

    end_time = time.time()  # Конец измерения времени
    logging.info(f"Время выполнения: {end_time - start_time} секунд")
    logging.info(f"Всего рассмотрено ключей: {TOTAL_KEY_ATTEMPTS}")
    logging.info(f"Успешных ключей: {SUCCESSFUL_KEY_ATTEMPTS}")

except FileNotFoundError as e:
    logging.error(f"Ошибка: {e}")
except Exception as e:
    logging.error(f"Произошла ошибка: {str(e)}")
