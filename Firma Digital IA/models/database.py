import mysql.connector
from mysql.connector import Error, pooling
from config.config import Config
import time

class Database:
    _pool = None
    
    def __init__(self):
        self.config = Config
        self._init_pool()
    
    def _init_pool(self):
        """Inicializar el pool de conexiones si no existe"""
        if Database._pool is None:
            try:
                Database._pool = pooling.MySQLConnectionPool(
                    pool_name='firma_pool',
                    pool_size=5,
                    pool_reset_session=True,
                    host=self.config.MYSQL_HOST,
                    database=self.config.MYSQL_DB,
                    user=self.config.MYSQL_USER,
                    password=self.config.MYSQL_PASSWORD,
                    charset='utf8mb4',
                    collation='utf8mb4_unicode_ci',
                    autocommit=False
                )
                print(" Pool de conexiones MySQL creado")
            except Error as e:
                print(f" Error creando pool: {e}")
                Database._pool = None
    
    def get_connection(self, retries=3):
        """Obtener conexión del pool con reintentos automáticos"""
        attempt = 0
        while attempt < retries:
            try:
                if Database._pool is None:
                    self._init_pool()
                
                if Database._pool:
                    connection = Database._pool.get_connection()
                    if connection and connection.is_connected():
                        return connection
            except Error as e:
                attempt += 1
                print(f"⚠️ Intento {attempt}/{retries} - Error conectando a MySQL: {e}")
                if attempt < retries:
                    time.sleep(1)  # Esperar 1 segundo antes de reintentar
                    Database._pool = None  # Reinicializar el pool
            
        print(f" No se pudo conectar a MySQL después de {retries} intentos")
        return None
    
    def init_db(self):
        """Inicializar la base de datos"""
        connection = self.get_connection()
        if connection:
            try:
                cursor = connection.cursor()
                print(" Conectado a la base de datos MySQL")
                
                # Verificar si las tablas existen
                cursor.execute("SHOW TABLES LIKE 'Usuarios'")
                if not cursor.fetchone():
                    print("⚠️ Las tablas no existen. Ejecuta el script base_firma.sql")
                
                connection.commit()
                
            except Error as e:
                print(f" Error inicializando BD: {e}")
            finally:
                cursor.close()
                connection.close()