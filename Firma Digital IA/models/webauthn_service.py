"""Módulo para WebAuthn / Autenticación Biométrica con sensor del dispositivo"""
import base64
import hashlib
import json
import os
from models.database import Database
from config.config import Config

class WebAuthnService:
    """Servicio para registrar y verificar huellas con WebAuthn"""
    
    def __init__(self):
        self.db = Database()
    
    def generate_registration_challenge(self, user_id, user_name, user_email):
        """Genera un challenge para registrar nueva huella"""
        import secrets
        from datetime import datetime, timedelta
        
        # Generar challenge aleatorio
        challenge = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
        
        # Guardar challenge temporalmente (en DB o caché)
        connection = self.db.get_connection()
        if not connection:
            raise Exception('No DB connection')
        
        cursor = None
        try:
            cursor = connection.cursor()
            
            # Crear tabla si no existe - simplificada
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS webauthn_challenges (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    challenge VARCHAR(500) NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    FOREIGN KEY (user_id) REFERENCES Usuarios(id_Usuario),
                    KEY idx_expires (expires_at)
                )
            """)
            connection.commit()
            
            # Insertar challenge
            expires_at = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute("""
                INSERT INTO webauthn_challenges (user_id, challenge, expires_at)
                VALUES (%s, %s, %s)
            """, (user_id, challenge, expires_at))
            connection.commit()
            print(f"✅ Challenge creado para user {user_id}")
            
        except Exception as e:
            print(f"❌ Error en generate_registration_challenge: {type(e).__name__}: {str(e)}")
            import traceback
            traceback.print_exc()
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
        
        # Retornar opciones para WebAuthn
        return {
            'challenge': challenge,
            'rp': {
                'name': 'Firma Digital',
                'id': 'localhost'
            },
            'user': {
                'id': base64.b64encode(str(user_id).encode()).decode('utf-8'),
                'name': user_name,
                'displayName': user_email
            },
            'pubKeyCredParams': [
                {'type': 'public-key', 'alg': -7},   # ES256
                {'type': 'public-key', 'alg': -257}  # RS256
            ],
            'timeout': 60000,
            'attestation': 'direct',
            'authenticatorSelection': {
                'authenticatorAttachment': 'platform',  # Solo sensor del dispositivo
                'userVerification': 'required'
            }
        }
    
    def register_credential(self, user_id, credential_id, public_key, sign_count=0):
        """Registra la credencial biométrica del usuario"""
        connection = self.db.get_connection()
        cursor = connection.cursor()
        
        try:
            # Tabla para credenciales WebAuthn
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS webauthn_credentials (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    credential_id VARCHAR(255) UNIQUE NOT NULL,
                    public_key TEXT NOT NULL,
                    sign_count INT DEFAULT 0,
                    transports VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES Usuarios(id_Usuario),
                    KEY (credential_id)
                )
            """)
            connection.commit()
            
            # Verificar si ya existe credencial
            cursor.execute("""
                SELECT id FROM webauthn_credentials 
                WHERE user_id = %s
            """, (user_id,))
            
            existing = cursor.fetchone()
            
            if existing:
                # Actualizar
                cursor.execute("""
                    UPDATE webauthn_credentials 
                    SET credential_id = %s, public_key = %s, sign_count = %s
                    WHERE user_id = %s
                """, (credential_id, public_key, sign_count, user_id))
            else:
                # Insertar
                cursor.execute("""
                    INSERT INTO webauthn_credentials 
                    (user_id, credential_id, public_key, sign_count)
                    VALUES (%s, %s, %s, %s)
                """, (user_id, credential_id, public_key, sign_count))
            
            # Actualizar en tabla de Usuarios
            cursor.execute("""
                UPDATE Usuarios 
                SET biometric_enabled = TRUE, fingerprint_hash = %s
                WHERE id_Usuario = %s
            """, (credential_id, user_id))
            
            connection.commit()
            return {'success': True, 'message': 'Huella registrada exitosamente'}
            
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
        finally:
            cursor.close()
            connection.close()
    
    def verify_credential(self, user_email, credential_id):
        """Verifica si la credencial pertenece al usuario"""
        connection = self.db.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        try:
            cursor.execute("""
                SELECT u.*, wc.public_key, wc.sign_count
                FROM Usuarios u
                LEFT JOIN webauthn_credentials wc ON u.id_Usuario = wc.user_id
                WHERE u.Email = %s AND u.biometric_enabled = TRUE
                AND wc.credential_id = %s
            """, (user_email, credential_id))
            
            result = cursor.fetchone()
            
            if result:
                # Actualizar último uso
                cursor.execute("""
                    UPDATE webauthn_credentials 
                    SET last_used = NOW()
                    WHERE credential_id = %s
                """, (credential_id,))
                connection.commit()
                
                return {
                    'success': True,
                    'user': result,
                    'message': 'Autenticación exitosa'
                }
            else:
                return {
                    'success': False,
                    'message': 'Credencial no reconocida'
                }
                
        except Exception as e:
            return {'success': False, 'message': str(e)}
        finally:
            cursor.close()
            connection.close()
    
    def get_user_credentials(self, user_id):
        """Obtiene las credenciales registradas del usuario"""
        connection = self.db.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        try:
            cursor.execute("""
                SELECT credential_id, created_at, last_used
                FROM webauthn_credentials
                WHERE user_id = %s
            """, (user_id,))
            
            return cursor.fetchall()
            
        finally:
            cursor.close()
            connection.close()

    def delete_user_biometrics(self, user_id):
        """Elimina todos los datos biométricos asociados al usuario."""
        connection = self.db.get_connection()
        if not connection:
            return {'success': False, 'message': 'Error de conexión'}

        cursor = None
        removed_files = 0
        try:
            cursor = connection.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS webauthn_credentials (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    credential_id VARCHAR(255) UNIQUE NOT NULL,
                    public_key TEXT NOT NULL,
                    sign_count INT DEFAULT 0,
                    transports VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES Usuarios(id_Usuario),
                    KEY (credential_id)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS webauthn_challenges (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    challenge VARCHAR(500) NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    FOREIGN KEY (user_id) REFERENCES Usuarios(id_Usuario),
                    KEY idx_expires (expires_at)
                )
            """)
            cursor.execute("DELETE FROM webauthn_credentials WHERE user_id = %s", (user_id,))
            deleted_credentials = cursor.rowcount

            cursor.execute("DELETE FROM webauthn_challenges WHERE user_id = %s", (user_id,))
            deleted_challenges = cursor.rowcount

            cursor.execute("""
                UPDATE Usuarios
                SET biometric_enabled = 0,
                    fingerprint_hash = NULL,
                    biometric_enrolled_date = NULL
                WHERE id_Usuario = %s
            """, (user_id,))

            connection.commit()

            template_folder = Config.BIOMETRIC_FOLDER
            user_template = os.path.join(template_folder, f"{user_id}.json")
            if os.path.exists(user_template):
                os.remove(user_template)
                removed_files += 1

            if os.path.isdir(template_folder):
                for filename in os.listdir(template_folder):
                    if not filename.endswith('.json') or filename == f"{user_id}.json":
                        continue
                    path = os.path.join(template_folder, filename)
                    try:
                        with open(path, 'r', encoding='utf-8') as file:
                            data = json.load(file)
                        if str(data.get('user_id')) == str(user_id):
                            os.remove(path)
                            removed_files += 1
                    except (OSError, json.JSONDecodeError):
                        continue

            return {
                'success': True,
                'message': 'Datos biométricos eliminados correctamente',
                'deleted_credentials': deleted_credentials,
                'deleted_challenges': deleted_challenges,
                'deleted_template_files': removed_files
            }
        except Exception as e:
            connection.rollback()
            return {'success': False, 'message': f'Error eliminando biometría: {str(e)}'}
        finally:
            if cursor:
                cursor.close()
            connection.close()
