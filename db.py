# api/db.py — Conexión a MySQL para FastAPI
import mysql.connector
from mysql.connector import pooling
from config import settings

# Pool de conexiones — más eficiente que abrir/cerrar en cada request
_pool = None

def get_pool():
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(
            pool_name="api_pool",
            pool_size=5,
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            database=settings.DB_NAME,
            user=settings.DB_USER,
            password=settings.DB_PASSWORD,
            autocommit=True,
            connection_timeout=10,
        )
    return _pool

def get_connection():
    """Obtiene una conexión del pool. Usar con context manager."""
    return get_pool().get_connection()


class DBConn:
    """Context manager para conexiones del pool."""
    def __enter__(self):
        self.conn = get_connection()
        self.cursor = self.conn.cursor(dictionary=True)
        return self.cursor, self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.cursor.close()
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass
