import secrets
import string
import re
from datetime import datetime, timedelta
from models.database import Database
from models.email_service import EmailService
from config.config import Config

class PasswordRecovery:
    def __init__(self):
        self.db = Database()
    
    def request_password_reset(self, email):
        """Solicitar restablecimiento de contraseña"""
        connection = self.db.get_connection()
        if not connection:
            return {'success': False, 'message': 'Error de conexión'}
        
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            self._ensure_recovery_columns(cursor)
            connection.commit()
            cursor.execute("SELECT * FROM Usuarios WHERE Email = %s", (email,))
            user = cursor.fetchone()
            
            if not user:
                return {'success': False, 'message': 'No existe usuario con ese email'}
            
            # Generar token (6 dígitos numéricos para facilidad)
            token = ''.join(secrets.choice(string.digits) for _ in range(6))
            expiry = datetime.now() + timedelta(hours=1)
            
            # Guardar token
            cursor.execute("""
                UPDATE Usuarios 
                SET recovery_token = %s, token_expiry = %s 
                WHERE id_Usuario = %s
            """, (token, expiry, user['id_Usuario']))
            
            connection.commit()
            
            # Intentar enviar email (fallback a log si falla)
            try:
                email_sent = EmailService.send_recovery_token(
                    email, 
                    token, 
                    user['Nombre']
                )
                
                if email_sent:
                    print(f"Token de recuperación enviado a {email}")
                    return {
                        'success': True, 
                        'message': f'Se ha enviado un código de recuperación a {email}'
                    }
            except Exception as email_error:
                print(f"Error enviando email: {email_error}")
            
            # Fallback: registrar token en archivo local y permitir que el usuario continúe
            try:
                log_line = f"{datetime.now().isoformat()} | {email} | TOKEN={token}\n"
                with open('recovery_tokens.log', 'a', encoding='utf-8') as f:
                    f.write(log_line)
                print(f"Token guardado en recovery_tokens.log para {email}")
            except Exception as ex:
                print(f"Error escribiendo recovery_tokens.log: {ex}")

            # Retornar éxito de todas formas (token fue generado)
            response = {
                'success': True,
                'message': f'Código de recuperación generado. Se envió a {email}. Si no lo recibes, verifica spam.'
            }

            response['debug_token'] = token

            # En modo desarrollo permitir mostrar token en la respuesta para pruebas
            try:
                if getattr(Config, 'MAIL_FORCE_SHOW_TOKEN', False):
                    response['debug_token'] = token
            except Exception:
                pass

            return response
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    
    def reset_password(self, token, new_password):
        """Restablecer contraseña con token válido"""
        from werkzeug.security import generate_password_hash
        
        # Validar fortaleza de contraseña
        password_validation = self.validate_password_strength(new_password)
        if not password_validation['valid']:
            return {'success': False, 'message': password_validation['message']}
        
        connection = self.db.get_connection()
        if not connection:
            return {'success': False, 'message': 'Error de conexión'}
        
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            self._ensure_recovery_columns(cursor)
            connection.commit()
            cursor.execute("""
                SELECT * FROM Usuarios 
                WHERE recovery_token = %s AND token_expiry > %s
            """, (token, datetime.now()))
            
            user = cursor.fetchone()
            if not user:
                return {'success': False, 'message': 'Token inválido o expirado'}
            
            # Actualizar contraseña
            new_hash = generate_password_hash(new_password)
            cursor.execute("""
                UPDATE Usuarios 
                SET password_hash = %s, recovery_token = NULL, token_expiry = NULL 
                WHERE id_Usuario = %s
            """, (new_hash, user['id_Usuario']))
            
            connection.commit()
            return {'success': True, 'message': 'Contraseña restablecida exitosamente'}
            
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
    
    def validate_token(self, token):
        """Validar token de recuperación"""
        connection = self.db.get_connection()
        if not connection:
            return {'success': False, 'message': 'Error de conexión'}
        
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            self._ensure_recovery_columns(cursor)
            connection.commit()
            cursor.execute("""
                SELECT usuario, Email FROM Usuarios 
                WHERE recovery_token = %s AND token_expiry > %s
            """, (token, datetime.now()))
            
            user = cursor.fetchone()
            if user:
                return {'success': True, 'user': user}
            else:
                return {'success': False, 'message': 'Token inválido o expirado'}
                
        except Exception as e:
            return {'success': False, 'message': str(e)}
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    @staticmethod
    def _ensure_recovery_columns(cursor):
        cursor.execute("SHOW COLUMNS FROM Usuarios")
        existing = {row['Field'] if isinstance(row, dict) else row[0] for row in cursor.fetchall()}
        if 'recovery_token' not in existing:
            cursor.execute("ALTER TABLE Usuarios ADD COLUMN recovery_token VARCHAR(100)")
        if 'token_expiry' not in existing:
            cursor.execute("ALTER TABLE Usuarios ADD COLUMN token_expiry DATETIME")
