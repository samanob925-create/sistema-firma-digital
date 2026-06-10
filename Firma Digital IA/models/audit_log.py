"""Módulo para registrar y obtener logs de acceso"""
from datetime import datetime
from models.database import Database

class AuditLog:
    """Servicio para auditoría y logs de acceso"""
    
    def __init__(self):
        self.db = Database()
    
    def crear_tabla(self):
        """Crear tabla de logs si no existe"""
        connection = self.db.get_connection()
        if not connection:
            return False
        
        cursor = connection.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Audit_Logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    usuario_id INT NOT NULL,
                    usuario_nombre VARCHAR(100),
                    email VARCHAR(120),
                    accion VARCHAR(100) NOT NULL,
                    detalles TEXT,
                    ip_address VARCHAR(50),
                    fecha_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (usuario_id) REFERENCES Usuarios(id_Usuario),
                    INDEX (usuario_id),
                    INDEX (fecha_hora)
                )
            """)
            connection.commit()
            return True
        except Exception as e:
            print(f"❌ Error creando tabla de logs: {e}")
            return False
        finally:
            cursor.close()
            connection.close()
    
    def registrar_acceso(self, usuario_id, usuario_nombre, email, ip_address=None):
        """Registra un acceso de usuario"""
        connection = self.db.get_connection()
        if not connection:
            return False
        
        cursor = connection.cursor()
        try:
            self.crear_tabla()  # Asegurar que existe
            
            cursor.execute("""
                INSERT INTO Audit_Logs 
                (usuario_id, usuario_nombre, email, accion, ip_address)
                VALUES (%s, %s, %s, 'LOGIN', %s)
            """, (usuario_id, usuario_nombre, email, ip_address))
            
            connection.commit()
            return True
        except Exception as e:
            print(f"❌ Error registrando acceso: {e}")
            return False
        finally:
            cursor.close()
            connection.close()
    
    def registrar_accion(self, usuario_id, accion, detalles=None, ip_address=None):
        """Registra una acción del usuario"""
        connection = self.db.get_connection()
        if not connection:
            return False
        
        cursor = connection.cursor()
        try:
            self.crear_tabla()  # Asegurar que existe
            
            cursor.execute("""
                INSERT INTO Audit_Logs 
                (usuario_id, accion, detalles, ip_address)
                VALUES (%s, %s, %s, %s)
            """, (usuario_id, accion, detalles, ip_address))
            
            connection.commit()
            return True
        except Exception as e:
            print(f"❌ Error registrando acción: {e}")
            return False
        finally:
            cursor.close()
            connection.close()
    
    def obtener_logs_usuarios(self, director_id, limit=100):
        """
        Obtiene logs de todos los usuarios (solo para Directors)
        Muestra quién entró, cuándo y desde dónde
        """
        connection = self.db.get_connection()
        if not connection:
            return []
        
        cursor = connection.cursor(dictionary=True)
        try:
            # Verificar que el usuario es Director
            cursor.execute("""
                SELECT rol FROM Usuarios WHERE id_Usuario = %s
            """, (director_id,))
            
            user = cursor.fetchone()
            if not user or user['rol'] != 'Director':
                print(f"⚠️ Usuario {director_id} no es Director - acceso denegado")
                return []
            
            # Obtener logs de acceso (LOGIN)
            cursor.execute("""
                SELECT 
                    al.id,
                    al.usuario_id,
                    al.usuario_nombre,
                    al.email,
                    al.accion,
                    al.detalles,
                    al.ip_address,
                    al.fecha_hora,
                    u.rol
                FROM Audit_Logs al
                LEFT JOIN Usuarios u ON al.usuario_id = u.id_Usuario
                WHERE al.accion = 'LOGIN'
                ORDER BY al.fecha_hora DESC
                LIMIT %s
            """, (limit,))
            
            return cursor.fetchall()
        except Exception as e:
            print(f"❌ Error obteniendo logs: {e}")
            return []
        finally:
            cursor.close()
            connection.close()
    
    def obtener_logs_usuario_especifico(self, usuario_id, limite_dias=30):
        """Obtiene el histórico de un usuario específico"""
        connection = self.db.get_connection()
        if not connection:
            return []
        
        cursor = connection.cursor(dictionary=True)
        try:
            self.crear_tabla()  # Asegurar que existe
            
            cursor.execute("""
                SELECT 
                    id, accion, detalles, ip_address, fecha_hora
                FROM Audit_Logs
                WHERE usuario_id = %s
                AND fecha_hora >= DATE_SUB(NOW(), INTERVAL %s DAY)
                ORDER BY fecha_hora DESC
            """, (usuario_id, limite_dias))
            
            return cursor.fetchall()
        except Exception as e:
            print(f"❌ Error obteniendo logs del usuario: {e}")
            return []
        finally:
            cursor.close()
            connection.close()
