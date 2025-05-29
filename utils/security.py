# utils/security.py
# Bu fayl parollarni xesh qilish va tekshirish kabi xavfsizlik funksiyalarini o'z ichiga oladi.

import bcrypt
import logging

logger = logging.getLogger(__name__)

def hash_password(password: str) -> str:
    """
    Berilgan parolni bcrypt yordamida xeshlaydi.
    """
    try:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        logger.info("Parol xeshlandi.")
        return hashed.decode('utf-8')
    except Exception as e:
        logger.error(f"Parolni xesh qilishda xato: {e}")
        return ""

def check_password(password: str, hashed_password: str) -> bool:
    """
    Berilgan parolni xeshlangan parol bilan solishtiradi.
    """
    try:
        is_valid = bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        if is_valid:
            logger.info("Parol muvaffaqiyatli tekshirildi.")
        else:
            logger.warning("Parol noto'g'ri.")
        return is_valid
    except Exception as e:
        logger.error(f"Parolni tekshirishda xato: {e}")
        return False

