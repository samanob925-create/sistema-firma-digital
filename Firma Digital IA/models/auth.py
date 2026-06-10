from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import re
from models.database import Database
from config.config import Config

class Auth:
    def __init__(self):
        self.secret_key = Config.SECRET_KEY
        self.db = Database()

    @staticmethod
    def _ensure_user_signature_columns(cursor):
        columns = {
            'curp': "ALTER TABLE Usuarios ADD COLUMN curp VARCHAR(18)",
            'cargo_firma': "ALTER TABLE Usuarios ADD COLUMN cargo_firma VARCHAR(150)",
            'ubicacion_firma': "ALTER TABLE Usuarios ADD COLUMN ubicacion_firma VARCHAR(255)"
        }
        cursor.execute("SHOW COLUMNS FROM Usuarios")
        existing = {row['Field'] if isinstance(row, dict) else row[0] for row in cursor.fetchall()}
        for column, statement in columns.items():
            if column not in existing:
                cursor.execute(statement)
    
    def login(self, username, password):
        """Login tradicional"""
        if not username or not password:
            return {'success': False, 'message': 'Usuario y contraseña son requeridos'}
        
        connection = self.db.get_connection()
        if not connection:
            return {'success': False, 'message': 'Error de conexión a la base de datos'}
        
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            self._ensure_user_signature_columns(cursor)
            connection.commit()
            cursor.execute("SELECT * FROM Usuarios WHERE usuario = %s", (username,))
            user = cursor.fetchone()
            
            if not user:
                return {'success': False, 'message': 'Credenciales incorrectas'}
            
            if not check_password_hash(user['password_hash'], password):
                return {'success': False, 'message': 'Credenciales incorrectas'}
            
            # Generar token JWT
            token = jwt.encode({
                'user_id': user['id_Usuario'],
                'username': user['usuario'],
                'nombre': user['Nombre'],
                'rol': user['rol'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, self.secret_key, algorithm='HS256')
            
            return {
                'success': True,
                'token': token,
                'user': {
                    'id': user['id_Usuario'],
                    'username': user['usuario'],
                    'nombre': user['Nombre'],
                    'rol': user['rol'],
                    'email': user.get('Email', ''),
                    'curp': user.get('curp', ''),
                    'cargo_firma': user.get('cargo_firma', ''),
                    'ubicacion_firma': user.get('ubicacion_firma', ''),
                    'biometric_enabled': bool(user.get('biometric_enabled', False))
                }
            }
            
        except Exception as e:
            print(f" Error en login: {str(e)}")
            return {'success': False, 'message': f'Error en el servidor: {str(e)}'}
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    def verify_token(self, token):
        """Verificar token JWT"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return {'success': True, 'payload': payload}
        except jwt.ExpiredSignatureError:
            return {'success': False, 'message': 'Token expirado'}
        except jwt.InvalidTokenError:
            return {'success': False, 'message': 'Token inválido'}

    def verify_password(self, user_id, password):
        """Verifica la contraseña de un usuario dado su id."""
        connection = self.db.get_connection()
        if not connection:
            return {'success': False, 'message': 'Error de conexión a la base de datos'}

        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT password_hash FROM Usuarios WHERE id_Usuario = %s", (user_id,))
            user = cursor.fetchone()
            if not user:
                return {'success': False, 'message': 'Usuario no encontrado'}

            if check_password_hash(user['password_hash'], password):
                return {'success': True}
            else:
                return {'success': False, 'message': 'Contraseña incorrecta'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    def validate_password_strength(self, password):
        """Valida que la contraseña tenga mínimo 10 caracteres y al menos 1 carácter especial"""
        if not password:
            return {'valid': False, 'message': 'La contraseña es requerida'}
        
        if len(password) < 10:
            return {'valid': False, 'message': 'La contraseña debe tener mínimo 10 caracteres'}
        
        # Verificar que tenga al menos un carácter especial
        special_chars = r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]'
        if not re.search(special_chars, password):
            return {'valid': False, 'message': 'La contraseña debe contener al menos 1 carácter especial (!@#$%^&*...). Ejemplo: Pass123!'}
        
        return {'valid': True, 'message': 'Contraseña válida'}

    def register_user(self, user_data):
        """Registrar nuevo usuario"""
        connection = self.db.get_connection()
        if not connection:
            return {'success': False, 'message': 'Error de conexión'}
        
        cursor = None
        try:
            # Validar fortaleza de contraseña
            password_validation = self.validate_password_strength(user_data.get('password', ''))
            if not password_validation['valid']:
                return {'success': False, 'message': password_validation['message']}
            
            cursor = connection.cursor()
            self._ensure_user_signature_columns(cursor)
            connection.commit()
            
            # Verificar si el usuario ya existe
            cursor.execute("SELECT id_Usuario FROM Usuarios WHERE usuario = %s OR Email = %s", 
                         (user_data['username'], user_data['email']))
            if cursor.fetchone():
                return {'success': False, 'message': 'Usuario o email ya existen'}
            
            # Crear hash de contraseña
            password_hash = generate_password_hash(user_data['password'])
            
            # Insertar nuevo usuario
            cursor.execute("""
                INSERT INTO Usuarios 
                (usuario, Nombre, Apellido_P, Apellido_M, Email, password_hash, rol, curp, cargo_firma, ubicacion_firma) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                user_data['username'],
                user_data['nombre'],
                user_data.get('apellido_p', ''),
                user_data.get('apellido_m', ''),
                user_data['email'],
                password_hash,
                user_data.get('rol', 'Subdirector'),
                (user_data.get('curp') or '').strip().upper(),
                (user_data.get('cargo_firma') or user_data.get('rol', 'Subdirector')).strip(),
                (user_data.get('ubicacion_firma') or '').strip()
            ))
            
            connection.commit()
            return {'success': True, 'message': 'Usuario registrado exitosamente'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
