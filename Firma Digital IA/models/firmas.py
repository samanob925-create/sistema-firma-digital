import hashlib
import rsa
import base64
from models.database import Database

class FirmaDigital:
    def __init__(self):
        self.db = Database()
    
    def generar_par_claves(self, key_size=2048):
        """Generar par de claves RSA"""
        (pubkey, privkey) = rsa.newkeys(key_size)
        return pubkey, privkey
    
    def firmar_documento(self, contenido, clave_privada):
        """Firmar un documento con RSA"""
        try:
            # Hash del contenido
            hash_content = hashlib.sha256(contenido.encode()).digest()
            
            # Firmar con RSA
            signature = rsa.sign(contenido.encode(), clave_privada, 'SHA-256')
            
            return {
                'success': True,
                'firma': base64.b64encode(signature).decode(),
                'hash': base64.b64encode(hash_content).decode()
            }
        except Exception as e:
            return {'success': False, 'message': f'Error firmando documento: {str(e)}'}
    
    def verificar_firma(self, contenido, firma, clave_publica):
        """Verificar una firma digital"""
        try:
            signature = base64.b64decode(firma)
            rsa.verify(contenido.encode(), signature, clave_publica)
            return {'success': True, 'message': 'Firma válida'}
        except rsa.VerificationError:
            return {'success': False, 'message': 'Firma inválida'}
        except Exception as e:
            return {'success': False, 'message': f'Error verificando firma: {str(e)}'}
    
    def guardar_firma_db(self, documento_id, usuario_id, contenido, algoritmo_hash='SHA-256', algoritmo_firma='RSA'):
        """Guardar firma en la base de datos"""
        connection = self.db.get_connection()
        if not connection:
            return {'success': False, 'message': 'Error de conexión'}
        
        cursor = None
        try:
            cursor = connection.cursor()
            
            # Generar claves
            pubkey, privkey = self.generar_par_claves()
            
            # Firmar documento
            firma_result = self.firmar_documento(contenido, privkey)
            if not firma_result['success']:
                return firma_result
            
            # Guardar en base de datos
            cursor.execute("""
                INSERT INTO Firma_Digital 
                (Algoritmo_hash, Algoritmo_firma, Firma_digital, Certificado_pub, Documento_id, Usuario_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                algoritmo_hash, 
                algoritmo_firma, 
                firma_result['firma'],
                pubkey.save_pkcs1().decode(), 
                documento_id, 
                usuario_id
            ))
            
            connection.commit()
            return {
                'success': True, 
                'firma_id': cursor.lastrowid,
                'clave_publica': pubkey.save_pkcs1().decode(),
                'firma_digital': firma_result['firma'],
                'hash_documento': firma_result['hash']
            }
            
        except Exception as e:
            connection.rollback()
            return {'success': False, 'message': str(e)}
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()