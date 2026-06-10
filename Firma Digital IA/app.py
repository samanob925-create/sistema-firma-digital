from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask import send_file, render_template_string
import jwt
import datetime
import os
import socket
from config.config import Config
from models.database import Database
from models.auth import Auth
from models.biometric import BiometricAuth
from models.password_recovery import PasswordRecovery
from models.firmas import FirmaDigital
from models.webauthn_service import WebAuthnService
from models.email_service import EmailService
from models.documentos_service import DocumentosService
from models.audit_log import AuditLog
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)
Config.init_app(app)

# Inicializar componentes
db = Database()
auth = Auth()
biometric = BiometricAuth()
password_recovery = PasswordRecovery()
firma_digital = FirmaDigital()
webauthn = WebAuthnService()
documentos_service = DocumentosService()
audit_log = AuditLog()


import os

os.makedirs("uploads", exist_ok=True)
os.makedirs("certificaciones", exist_ok=True)
os.makedirs("keys", exist_ok=True)

# Inicializar base de datos
db.init_db()

def get_public_base_url():
    """Devuelve una URL que tambien pueda abrirse desde otro dispositivo en la red local."""
    configured = getattr(Config, 'PUBLIC_BASE_URL', '').strip() if hasattr(Config, 'PUBLIC_BASE_URL') else ''
    if configured:
        return configured.rstrip('/')

    host_url = request.host_url.rstrip('/')
    host = request.host.split(':', 1)[0].lower()
    if host in ('localhost', '127.0.0.1'):
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            port = request.host.split(':', 1)[1] if ':' in request.host else '5000'
            return f'{request.scheme}://{local_ip}:{port}'
        except Exception:
            return host_url
    return host_url

from typing import Dict, Any, Optional, Callable, Tuple
from functools import wraps
import base64
import hashlib
import secrets
import re
import textwrap

class DeclarativeValidators:
    """Validadores sin efectos secundarios"""
    
    @staticmethod
    def has_required_fields(data: Dict, required_fields: list) -> Tuple[bool, Optional[str]]:
        """Verifica campos requeridos de forma declarativa"""
        missing = [field for field in required_fields if not data.get(field)]
        if missing:
            return False, f'Campo {missing[0]} es requerido'
        return True, None
    
    @staticmethod
    def is_valid_token(auth_header: Optional[str]) -> bool:
        """Valida formato de token"""
        return bool(auth_header and auth_header.startswith('Bearer '))
    
    @staticmethod
    def extract_token(auth_header: str) -> str:
        """Extrae token del header (funciÃ³n pura)"""
        return auth_header.replace('Bearer ', '')
    
    @staticmethod
    def is_valid_file_extension(filename: str, allowed_extensions: set) -> bool:
        """Valida extensiÃ³n de archivo"""
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

# ========== 2. PROCESADOR DECLARATIVO DE HUELLAS ==========
class DeclarativeFingerprintProcessor:
    """Procesamiento de huellas sin efectos secundarios"""
    
    @staticmethod
    def extract_from_request(request_json: Optional[Dict], request_files) -> Optional[bytes]:
        """Extrae imagen de huella de forma declarativa"""
        # Prioridad: archivo > JSON base64
        if request_files and 'fingerprint_image' in request_files:
            file = request_files['fingerprint_image']
            return file.read() if hasattr(file, 'read') else None
        
        if request_json and 'fingerprint_image' in request_json:
            try:
                return base64.b64decode(request_json['fingerprint_image'])
            except:
                return None
        
        return None
    
    @staticmethod
    def generate_credential_id(attestation_object: Optional[str] = None) -> str:
        """Genera credential ID de forma declarativa"""
        if attestation_object:
            try:
                decoded = base64.b64decode(attestation_object)
                return base64.b64encode(hashlib.sha256(decoded).digest()).decode('utf-8')
            except:
                pass
        return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    @staticmethod
    def extract_credential_id_from_raw(raw_body: str) -> Optional[str]:
        """Extrae credential_id de raw body de forma declarativa"""
        patterns = [r'"credential_id"\s*:\s*"([^"]+)"', r'"rawId"\s*:\s*"([^"]+)"', r'"id"\s*:\s*"([^"]+)"']
        for pattern in patterns:
            match = re.search(pattern, raw_body)
            if match:
                return match.group(1)
        return None

# ========== 3. FORMATEADOR DECLARATIVO DE DOCUMENTOS ==========
class DeclarativeDocumentFormatter:
    """Formateo de documentos sin efectos secundarios"""
    
    @staticmethod
    def format_size(size_bytes: Optional[int]) -> str:
        """Formatea tamaÃ±o de archivo"""
        if not size_bytes:
            return "N/A"
        return f"{(size_bytes / 1024):.2f} KB"
    
    @staticmethod
    def format_date(date_obj) -> Optional[str]:
        """Formatea fecha"""
        return date_obj.isoformat() if date_obj else None
    
    @staticmethod
    def transform_document(doc: Dict) -> Dict:
        """Transforma documento de forma declarativa"""
        return {
            **doc,
            'tamano': doc.get('tamaño') or doc.get('tamaÃ±o'),
            'tamano_formateado': DeclarativeDocumentFormatter.format_size(doc.get('tamaño') or doc.get('tamaÃ±o')),
            'tamaÃ±o_formateado': DeclarativeDocumentFormatter.format_size(doc.get('tamaño') or doc.get('tamaÃ±o')),
            'fecha_subida': DeclarativeDocumentFormatter.format_date(doc.get('fecha_subida'))
        }

# ========== 4. CONSTRUCTOR DECLARATIVO DE RESPUESTAS ==========
class DeclarativeResponseBuilder:
    """ConstrucciÃ³n de respuestas sin efectos secundarios"""
    
    @staticmethod
    def success(data: Any = None, message: str = "Success") -> Dict:
        response = {'success': True, 'message': message}
        if data is not None:
            response['data'] = data
        return response
    
    @staticmethod
    def error(message: str, status_code: int = 400) -> Tuple[Dict, int]:
        return {'success': False, 'message': message}, status_code
    
    @staticmethod
    def with_documents(documents: list, message: str = "Documentos obtenidos") -> Dict:
        formatted_docs = [DeclarativeDocumentFormatter.transform_document(doc) for doc in documents]
        return {
            'success': True,
            'message': message,
            'documentos': formatted_docs,
            'total': len(formatted_docs)
        }
    
    @staticmethod
    def health(db_connected: bool, error_msg: Optional[str] = None) -> Tuple[Dict, int]:
        if db_connected:
            return {'success': True, 'status': 'ok', 'database': 'connected'}, 200
        else:
            response = {'success': False, 'status': 'error', 'database': 'disconnected'}
            if error_msg:
                response['message'] = error_msg
            return response, 503

# ========== 5. DECORADOR DECLARATIVO DE AUTENTICACIÃ“N ==========
def declarative_auth_required(f: Callable) -> Callable:
    """Decorador puro para validaciÃ³n de autenticaciÃ³n"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request, jsonify
        
        auth_header = request.headers.get('Authorization')
        if not DeclarativeValidators.is_valid_token(auth_header):
            return jsonify({'success': False, 'message': 'Token requerido'}), 401
        
        token = DeclarativeValidators.extract_token(auth_header)
        return f(*args, **kwargs, validated_token=token)
    return decorated_function

# ========== 6. SERVICIO DECLARATIVO DE BASE DE DATOS ==========
class DeclarativeDatabaseService:
    """Operaciones de BD envueltas en funciones declarativas"""
    
    @staticmethod
    def check_connection(db_instance) -> Tuple[bool, Optional[str]]:
        """Verifica conexiÃ³n a BD de forma declarativa"""
        try:
            conn = db_instance.get_connection()
            if conn and conn.is_connected():
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                cursor.close()
                conn.close()
                return True, None
            return False, "Disconnected"
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def get_user_by_username(db_instance, username: str) -> Optional[Dict]:
        """Obtiene usuario por username (funciÃ³n pura con efecto controlado)"""
        try:
            conn = db_instance.get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id_Usuario, Nombre, Email FROM Usuarios WHERE usuario = %s", (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            return user
        except:
            return None

# ========== RUTAS PRINCIPALES ==========

@app.route('/')
def index():
    return render_template('index.html', recaptcha_site_key=Config.RECAPTCHA_SITE_KEY)

# FUNCIÃ“N 1: health_check (declarativa)
@app.route('/api/health', methods=['GET'])
def health_check():
    """Verificar estado del servidor y la BD - VersiÃ³n declarativa"""
    connected, error = DeclarativeDatabaseService.check_connection(db)
    response, status_code = DeclarativeResponseBuilder.health(connected, error)
    return jsonify(response), status_code

# FUNCIÃ“N 2: login (declarativa)
@app.route('/api/login', methods=['POST'])
def login():
    """Login tradicional - Version declarativa"""
    data = request.get_json()
    
    # ValidaciÃ³n declarativa
    is_valid, error_msg = DeclarativeValidators.has_required_fields(data, ['username', 'password'])
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg})
    
    result = auth.login(data.get('username'), data.get('password'))
    
    # Registro de acceso declarativo
    if result.get('success'):
        ip_address = request.remote_addr
        user = DeclarativeDatabaseService.get_user_by_username(db, data.get('username'))
        if user:
            try:
                audit_log.registrar_acceso(user['id_Usuario'], user['Nombre'], user['Email'], ip_address)
            except Exception as e:
                print(f"âš ï¸ No se pudo registrar acceso: {e}")
    
    return jsonify(result)

# FUNCIÃ“N 3: register (declarativa)
@app.route('/api/register', methods=['POST'])
def register():
    """Registrar nuevo usuario - VersiÃ³n declarativa"""
    data = request.get_json()
    
    is_valid, error_msg = DeclarativeValidators.has_required_fields(data, [
        'username', 'password', 'email', 'nombre', 'curp', 'cargo_firma', 'ubicacion_firma'
    ])
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg})

    data['curp'] = (data.get('curp') or '').strip().upper()
    if not re.match(r'^[A-Z0-9]{18}$', data['curp']):
        return jsonify({'success': False, 'message': 'La CURP debe tener 18 caracteres alfanumericos'}), 400
    
    result = auth.register_user(data)
    return jsonify(result)

# ========== AUTENTICACIÃ“N BIOMÃ‰TRICA CON SENSOR DE HUELLA ==========

# FUNCIÃ“N 4: enroll_fingerprint (declarativa)
@app.route('/api/biometric/fingerprint/enroll', methods=['POST'])
def enroll_fingerprint():
    """Registra nueva huella - VersiÃ³n declarativa"""
    try:
        auth_header = request.headers.get('Authorization')
        if not DeclarativeValidators.is_valid_token(auth_header):
            return jsonify({'success': False, 'message': 'Token requerido'}), 401
        
        token = DeclarativeValidators.extract_token(auth_header)
        auth_result = auth.verify_token(token)
        if not auth_result['success']:
            return jsonify(auth_result), 401
        
        user_id = auth_result['payload']['user_id']
        
        # ExtracciÃ³n declarativa de huella
        request_json = request.get_json() if request.is_json else None
        fingerprint_image = DeclarativeFingerprintProcessor.extract_from_request(request_json, request.files)
        
        if not fingerprint_image:
            return jsonify({'success': False, 'message': 'Imagen de huella requerida'})
        
        quality_score = request.form.get('quality_score') or (request_json.get('quality_score') if request_json else None)
        result = biometric.enroll_fingerprint(user_id, fingerprint_image, quality_score)
        
        if result['success']:
            try:
                EmailService.send_biometric_confirmation(
                    auth_result['payload'].get('email', ''),
                    auth_result['payload'].get('nombre', '')
                )
            except:
                pass
        
        return jsonify(result)
    except Exception as e:
        print(f"âŒ Error enroll_fingerprint: {str(e)}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# FUNCIÃ“N 5: verify_fingerprint (declarativa)
@app.route('/api/biometric/fingerprint/verify', methods=['POST'])
def verify_fingerprint():
    """Verifica huella - VersiÃ³n declarativa"""
    try:
        auth_header = request.headers.get('Authorization')
        if not DeclarativeValidators.is_valid_token(auth_header):
            return jsonify({'success': False, 'message': 'Token requerido'}), 401
        
        token = DeclarativeValidators.extract_token(auth_header)
        auth_result = auth.verify_token(token)
        if not auth_result['success']:
            return jsonify(auth_result), 401
        
        user_id = auth_result['payload']['user_id']
        
        request_json = request.get_json() if request.is_json else None
        fingerprint_image = DeclarativeFingerprintProcessor.extract_from_request(request_json, request.files)
        
        if not fingerprint_image:
            return jsonify({'success': False, 'message': 'Imagen de huella requerida'})
        
        result = biometric.verify_fingerprint(user_id, fingerprint_image)
        return jsonify(result)
    except Exception as e:
        print(f"âŒ Error verify_fingerprint: {str(e)}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
# FUNCIÃ“N 6: identify_fingerprint (declarativa)
@app.route('/api/biometric/fingerprint/identify', methods=['POST'])
def identify_fingerprint():
    """Identifica usuario por huella - VersiÃ³n declarativa"""
    try:
        request_json = request.get_json() if request.is_json else None
        fingerprint_image = DeclarativeFingerprintProcessor.extract_from_request(request_json, request.files)
        
        if not fingerprint_image:
            return jsonify({'success': False, 'message': 'Imagen de huella requerida'})
        
        result = biometric.identify_fingerprint(fingerprint_image)
        
        if result['success']:
            user_id = result['user_id']
            connection = db.get_connection()
            cursor = connection.cursor(dictionary=True)
            try:
                cursor.execute("""
                    SELECT id_Usuario, usuario, Nombre, rol, Email, biometric_enabled
                    FROM Usuarios WHERE id_Usuario = %s
                """, (user_id,))
                user = cursor.fetchone()
                
                if user:
                    token = jwt.encode({
                        'user_id': user['id_Usuario'],
                        'username': user['usuario'],
                        'nombre': user['Nombre'],
                        'rol': user['rol'],
                        'email': user.get('Email', ''),
                        'biometric_auth': True,
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                    }, Config.SECRET_KEY, algorithm='HS256')
                    
                    result['token'] = token
                    result['user'] = user
            finally:
                cursor.close()
                connection.close()
        
        return jsonify(result)
    except Exception as e:
        print(f"âŒ Error identify_fingerprint: {str(e)}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# ========== AUTENTICACIÃ“N BIOMÃ‰TRICA CON WEBAUTHN ==========


# FUNCIÃ“N 7: register_biometric (declarativa)
@app.route('/api/biometric/register', methods=['POST'])
def register_biometric():
    """Registra credencial biomÃ©trica - VersiÃ³n declarativa"""
    try:
        auth_header = request.headers.get('Authorization')
        if not DeclarativeValidators.is_valid_token(auth_header):
            return jsonify({'success': False, 'message': 'Token requerido'}), 401
        
        token = DeclarativeValidators.extract_token(auth_header)
        auth_result = auth.verify_token(token)
        if not auth_result['success']:
            return jsonify(auth_result), 401
        
        user_id = auth_result['payload']['user_id']
        
        try:
            data = request.get_json(force=False)
        except:
            data = None
        
        if not data:
            raw_body = request.get_data(as_text=True)
            credential_id = DeclarativeFingerprintProcessor.extract_credential_id_from_raw(raw_body)
            attestation_obj = re.search(r'"attestation_object"\s*:\s*"([^"]+)"', raw_body)
            attestation_obj = attestation_obj.group(1) if attestation_obj else ''
        else:
            credential_id = data.get('credential_id')
            attestation_obj = data.get('attestation_object', '')
        
        if not credential_id:
            credential_id = DeclarativeFingerprintProcessor.generate_credential_id(attestation_obj)
        
        result = webauthn.register_credential(user_id, credential_id, attestation_obj)
        
        if result.get('success'):
            try:
                EmailService.send_biometric_confirmation(
                    auth_result['payload'].get('email', ''),
                    auth_result['payload'].get('nombre', '')
                )
            except:
                pass
        
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Error registrando huella', 'error': str(e)}), 500

# FUNCIÃ“N 8: verify_biometric (declarativa)
@app.route('/api/biometric/verify', methods=['POST'])
def verify_biometric():
    """Verifica autenticaciÃ³n biomÃ©trica - VersiÃ³n declarativa"""
    data = request.get_json()
    credential_id = data.get('credential_id') if data else None
    
    if not credential_id:
        return jsonify({'success': False, 'message': 'Credential ID requerido'})
    
    from models.database import Database
    db_conn = Database()
    connection = db_conn.get_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        auth._ensure_user_signature_columns(cursor)
        connection.commit()
        cursor.execute("""
            SELECT u.*, wc.credential_id FROM Usuarios u
            INNER JOIN webauthn_credentials wc ON u.id_Usuario = wc.user_id
            WHERE wc.credential_id = %s AND u.biometric_enabled = TRUE
        """, (credential_id,))
        
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'success': False, 'message': 'Huella no reconocida'})
        
        token = jwt.encode({
            'user_id': user['id_Usuario'],
            'username': user['usuario'],
            'nombre': user['Nombre'],
            'rol': user['rol'],
            'email': user.get('Email', ''),
            'credential_id': credential_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, Config.SECRET_KEY, algorithm='HS256')
        
        return jsonify({
            'success': True,
            'message': 'AutenticaciÃ³n biomÃ©trica exitosa',
            'token': token,
            'credential_id': credential_id,
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
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        cursor.close()
        connection.close()
       

# FUNCIÃ“N 9: request_password_recovery (declarativa)
@app.route('/api/biometric', methods=['DELETE'])
def delete_biometric():
    """Elimina todos los datos biomÃ©tricos del usuario autenticado."""
    auth_header = request.headers.get('Authorization')
    if not DeclarativeValidators.is_valid_token(auth_header):
        return jsonify({'success': False, 'message': 'Token requerido'}), 401

    token = DeclarativeValidators.extract_token(auth_header)
    auth_result = auth.verify_token(token)
    if not auth_result['success']:
        return jsonify(auth_result), 401

    user_id = auth_result['payload']['user_id']
    result = webauthn.delete_user_biometrics(user_id)
    return jsonify(result), 200 if result.get('success') else 500

@app.route('/api/password/recovery', methods=['POST'])
def request_password_recovery():
    """Solicitar recuperaciÃ³n de contraseÃ±a - VersiÃ³n declarativa"""
    data = request.get_json()
    email = data.get('email') if data else None
    
    if not email:
        return jsonify({'success': False, 'message': 'Email requerido'})
    
    result = password_recovery.request_password_reset(email)
    return jsonify(result)

# FUNCIÃ“N 10: reset_password (declarativa)
@app.route('/api/password/reset', methods=['POST'])
def reset_password():
    """Restablecer contraseÃ±a - VersiÃ³n declarativa"""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'message': 'Datos requeridos'})
    
    token = data.get('token')
    new_password = data.get('new_password')
    
    if not token or not new_password:
        return jsonify({'success': False, 'message': 'Token y nueva contraseÃ±a requeridos'})
    
    result = password_recovery.reset_password(token, new_password)
    return jsonify(result)

# FUNCIÃ“N 11: validate_token (declarativa)
@app.route('/api/password/validate-token', methods=['POST'])
def validate_token():
    """Validar token de recuperaciÃ³n - VersiÃ³n declarativa"""
    data = request.get_json()
    token = data.get('token') if data else None
    
    if not token:
        return jsonify({'success': False, 'message': 'Token requerido'})
    
    result = password_recovery.validate_token(token)
    return jsonify(result)

# ========== FIRMAS DIGITALES ==========

@app.route('/api/firmas/generar', methods=['POST'])
def generar_firma():
    """Generar firma digital para documento"""
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'success': False, 'message': 'Token requerido'}), 401
    
    auth_result = auth.verify_token(token.replace('Bearer ', ''))
    if not auth_result['success']:
        return jsonify(auth_result), 401
    
    data = request.get_json()
    documento_id = data.get('documento_id')
    razon = data.get('razon', 'Firma digital')
    ubicacion = data.get('ubicacion', '')
    
    if not documento_id:
        return jsonify({'success': False, 'message': 'Documento ID requerido'})
    
    user_id = auth_result['payload']['user_id']
    
    # Usar documentos_service para firmar (que usa Documentos_PDF, no la tabla vieja Documento)
    result = documentos_service.firmar_documento(
        documento_id, user_id, razon, ubicacion,
        verification_base_url=get_public_base_url()
    )
    
    return jsonify(result)

@app.route('/verificar/<codigo_verificacion>', methods=['GET'])
def ver_constancia_verificacion(codigo_verificacion):
    """Pagina publica de solo lectura para verificar una firma por QR."""
    result = documentos_service.obtener_constancia_por_codigo(codigo_verificacion)
    if not result.get('success'):
        return render_template_string("""
            <!doctype html><html lang="es"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Firma no encontrada</title>
            <style>body{font-family:Arial,sans-serif;background:#f3f4f6;color:#111827;margin:0;padding:32px}
            main{max-width:720px;margin:auto;background:white;border:1px solid #e5e7eb;border-radius:8px;padding:28px}</style>
            </head><body><main><h1>Firma no encontrada</h1>
            <p>El codigo de verificacion no existe o el documento ya no esta disponible.</p></main></body></html>
        """), 404

    data = result['firma']
    return render_template_string("""
        <!doctype html>
        <html lang="es">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Verificacion de firma digital</title>
            <style>
                body{font-family:Arial,sans-serif;background:#f3f4f6;color:#111827;margin:0;padding:28px}
                main{max-width:1040px;margin:auto;background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:28px}
                h1{font-size:24px;margin:0 0 6px}.ok{color:#047857;font-weight:700;margin-bottom:22px}
                dl{display:grid;grid-template-columns:220px 1fr;gap:12px 18px}dt{font-weight:700;color:#374151}dd{margin:0;word-break:break-word}
                .hash{font-family:Consolas,monospace;font-size:12px}.actions{margin-top:24px}
                a{display:inline-block;background:#2563eb;color:white;text-decoration:none;padding:12px 16px;border-radius:6px;font-weight:700}
                iframe{width:100%;height:720px;border:1px solid #d1d5db;border-radius:6px;margin-top:16px;background:#f9fafb}
                h2{font-size:18px;margin-top:26px}
                @media(max-width:640px){dl{grid-template-columns:1fr}body{padding:14px}main{padding:18px}}
            </style>
        </head>
        <body>
            <main>
                <h1>Verificacion de firma digital</h1>
                <div class="ok">Documento firmado y registrado en el sistema</div>
                <dl>
                    <dt>Documento</dt><dd>{{ data.titulo }}</dd>
                    <dt>ID documento</dt><dd>{{ data.documento_id }}</dd>
                    <dt>Firmante</dt><dd>{{ data.firmante_nombre }}</dd>
                    <dt>CURP</dt><dd>{{ data.firmante_curp }}</dd>
                    <dt>Cargo</dt><dd>{{ data.firmante_cargo }}</dd>
                    <dt>Ubicacion</dt><dd>{{ data.ubicacion }}</dd>
                    <dt>Razon</dt><dd>{{ data.razon }}</dd>
                    <dt>Fecha de firma</dt><dd>{{ data.fecha_firma }}</dd>
                    <dt>Algoritmo</dt><dd>{{ data.algoritmo_firma }}</dd>
                    <dt>Codigo</dt><dd>{{ data.codigo_verificacion }}</dd>
                    <dt>Hash SHA256</dt><dd class="hash">{{ data.hash_documento }}</dd>
                </dl>
                {% if data.tiene_documento %}
                <div class="actions">
                    <a href="/documento-verificado/{{ data.codigo_verificacion }}" target="_blank" rel="noopener">Abrir documento de solo lectura</a>
                </div>
                <h2>Documento firmado</h2>
                <iframe src="/documento-verificado/{{ data.codigo_verificacion }}#toolbar=0&navpanes=0"></iframe>
                {% endif %}
            </main>
        </body>
        </html>
    """, data=data)

@app.route('/documento-verificado/<codigo_verificacion>', methods=['GET'])
def documento_verificado_publico(codigo_verificacion):
    """Sirve el PDF firmado en modo inline para consulta publica de solo lectura."""
    result = documentos_service.obtener_constancia_por_codigo(codigo_verificacion)
    if not result.get('success') or not result['firma'].get('ruta_archivo_firmado'):
        return jsonify({'success': False, 'message': 'Documento no encontrado'}), 404

    ruta = result['firma']['ruta_archivo_firmado']
    if not os.path.exists(ruta):
        return jsonify({'success': False, 'message': 'Archivo no disponible'}), 404
    return send_file(ruta, as_attachment=False, mimetype='application/pdf')

@app.route('/api/firmas/consultar', methods=['POST'])
def consultar_firma_por_codigo():
    """Consulta datos de firma por codigo de verificacion, firma o hash."""
    data = request.get_json() or {}
    clave = (data.get('clave') or data.get('codigo') or '').strip()
    if not clave:
        return jsonify({'success': False, 'message': 'Ingresa una clave, codigo, firma o hash'}), 400
    result = documentos_service.buscar_firma_por_clave(clave)
    return jsonify(result), 200 if result.get('success') else 404

@app.route('/api/firmas/verificar', methods=['POST'])
def verificar_firma():
    """Verificar firma digital"""
    data = request.get_json()
    contenido = data.get('contenido')
    firma = data.get('firma')
    clave_publica_pem = data.get('clave_publica')
    
    if not all([contenido, firma, clave_publica_pem]):
        return jsonify({'success': False, 'message': 'Contenido, firma y clave pÃºblica requeridos'})
    
    try:
        # Cargar clave pÃºblica
        import rsa
        pubkey = rsa.PublicKey.load_pkcs1(clave_publica_pem.encode())
        result = firma_digital.verificar_firma(contenido, firma, pubkey)
    except Exception as e:
        result = {'success': False, 'message': f'Error cargando clave pÃºblica: {str(e)}'}
    
    return jsonify(result)

# FUNCIÃ“N 12: get_user_profile (declarativa)
@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    """Obtener perfil del usuario - Version declarativa"""
    auth_header = request.headers.get('Authorization')
    if not DeclarativeValidators.is_valid_token(auth_header):
        return jsonify({'success': False, 'message': 'Token requerido'}), 401
    
    token = DeclarativeValidators.extract_token(auth_header)
    auth_result = auth.verify_token(token)
    if not auth_result['success']:
        return jsonify(auth_result), 401
    
    user_id = auth_result['payload']['user_id']
    
    connection = db.get_connection()
    if not connection:
        return jsonify({'success': False, 'message': 'Error de conexiÃ³n'}), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        auth._ensure_user_signature_columns(cursor)
        connection.commit()
        cursor.execute("""
            SELECT id_Usuario, usuario, Nombre, Apellido_P, Apellido_M, Email, rol,
                   curp, cargo_firma, ubicacion_firma, biometric_enabled
            FROM Usuarios WHERE id_Usuario = %s
        """, (user_id,))
        
        user = cursor.fetchone()
        if user:
            return jsonify({'success': True, 'user': user})
        return jsonify({'success': False, 'message': 'Usuario no encontrado'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/api/dashboard/resumen', methods=['GET'])
def dashboard_resumen():
    """Resumen operativo para alimentar el dashboard principal."""
    auth_header = request.headers.get('Authorization')
    if not DeclarativeValidators.is_valid_token(auth_header):
        return jsonify({'success': False, 'message': 'Token requerido'}), 401

    token = DeclarativeValidators.extract_token(auth_header)
    auth_result = auth.verify_token(token)
    if not auth_result['success']:
        return jsonify(auth_result), 401

    user_id = auth_result['payload']['user_id']
    user_role = (auth_result['payload'].get('rol') or '').lower()

    connection = db.get_connection()
    if not connection:
        return jsonify({'success': False, 'message': 'Error de conexión'}), 500

    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("SHOW TABLES LIKE 'Documentos_PDF'")
        has_docs_table = bool(cursor.fetchone())
        cursor.execute("SHOW TABLES LIKE 'Firmas_Documentos'")
        has_signatures_table = bool(cursor.fetchone())

        documentos_pendientes = 0
        total_documentos = 0
        total_firmas = 0
        firmas_hoy = 0
        actividad = []
        documentos_firmados = []

        if has_docs_table:
            cursor.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN estado = 'Pendiente' THEN 1 ELSE 0 END) AS pendientes
                FROM Documentos_PDF
                WHERE usuario_id = %s
            """, (user_id,))
            doc_counts = cursor.fetchone() or {}
            total_documentos = int(doc_counts.get('total') or 0)
            documentos_pendientes = int(doc_counts.get('pendientes') or 0)

        if has_signatures_table:
            documentos_service._ensure_signature_columns(cursor)
            connection.commit()

            firma_where = "" if user_role == 'director' else "WHERE fd.usuario_id = %s"
            firma_params = () if user_role == 'director' else (user_id,)

            cursor.execute(f"""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN DATE(fecha_firma) = CURDATE() THEN 1 ELSE 0 END) AS hoy
                FROM Firmas_Documentos
                {firma_where}
            """, firma_params)
            signature_counts = cursor.fetchone() or {}
            total_firmas = int(signature_counts.get('total') or 0)
            firmas_hoy = int(signature_counts.get('hoy') or 0)

            actividad_where = "" if user_role == 'director' else "WHERE fd.usuario_id = %s"
            actividad_params = () if user_role == 'director' else (user_id,)

            cursor.execute(f"""
                SELECT dp.id, dp.titulo, dp.estado, dp.ruta_archivo_firmado, fd.fecha_firma,
                       fd.algoritmo_firma, fd.codigo_verificacion, fd.qr_code,
                       fd.firmante_nombre, fd.firmante_curp, fd.firmante_cargo,
                       u.Nombre AS firmado_por
                FROM Firmas_Documentos fd
                INNER JOIN Documentos_PDF dp ON dp.id = fd.documento_id
                LEFT JOIN Usuarios u ON u.id_Usuario = fd.usuario_id
                {actividad_where}
                ORDER BY fd.fecha_firma DESC
                LIMIT 10
            """, actividad_params)
            actividad = cursor.fetchall()
            documentos_firmados = actividad

        cursor.execute("SELECT COUNT(*) AS total FROM Usuarios")
        usuarios_activos = int((cursor.fetchone() or {}).get('total') or 0)

        if user_role == 'director':
            cursor.execute("""
                SELECT id_Usuario AS id, usuario, Nombre AS nombre, Email AS email, rol
                FROM Usuarios
                ORDER BY Nombre ASC
                LIMIT 100
            """)
        else:
            cursor.execute("""
                SELECT id_Usuario AS id, usuario, Nombre AS nombre, Email AS email, rol
                FROM Usuarios
                WHERE id_Usuario = %s
            """, (user_id,))
        usuarios = cursor.fetchall()

        return jsonify({
            'success': True,
            'stats': {
                'total_firmas': total_firmas,
                'documentos_pendientes': documentos_pendientes,
                'usuarios_activos': usuarios_activos,
                'firmas_hoy': firmas_hoy,
                'total_documentos': total_documentos
            },
            'actividad': actividad,
            'documentos_firmados': documentos_firmados,
            'usuarios': usuarios
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

# ========== GESTIÃ“N DE DOCUMENTOS ==========

# FUNCIÃ“N 15: subir_documento (declarativa)
@app.route('/api/documentos/subir', methods=['POST'])
def subir_documento():
    """Sube documento - VersiÃ³n declarativa"""
    auth_header = request.headers.get('Authorization')
    if not DeclarativeValidators.is_valid_token(auth_header):
        return jsonify({'success': False, 'message': 'Token requerido'}), 401
    
    token = DeclarativeValidators.extract_token(auth_header)
    auth_result = auth.verify_token(token)
    if not auth_result['success']:
        return jsonify(auth_result), 401
    
    user_id = auth_result['payload']['user_id']
    
    # Validaciones declarativas
    if 'archivo' not in request.files:
        return jsonify({'success': False, 'message': 'Archivo requerido'})
    
    archivo = request.files['archivo']
    if archivo.filename == '':
        return jsonify({'success': False, 'message': 'Archivo invÃ¡lido'})
    
    allowed_extensions = {'pdf', 'txt', 'doc', 'docx'}
    if not DeclarativeValidators.is_valid_file_extension(archivo.filename, allowed_extensions):
        return jsonify({'success': False, 'message': 'Solo se permiten archivos: PDF, TXT, DOC, DOCX'})
    
    titulo = request.form.get('titulo', 'Documento sin tÃ­tulo')
    descripcion = request.form.get('descripcion', '')
    
    result = documentos_service.subir_documento(titulo, user_id, archivo, descripcion)
    
    if result['success']:
        result['message'] = f'Documento "{titulo}" subido exitosamente. Puedes firmarlo desde la secciÃ³n de GestiÃ³n de Firma.'
    
    return jsonify(result)

@app.route('/api/documentos/listar', methods=['GET'])
def listar_documentos():
    """Lista los documentos del usuario"""
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'success': False, 'message': 'Token requerido'}), 401
    
    auth_result = auth.verify_token(token.replace('Bearer ', ''))
    if not auth_result['success']:
        return jsonify(auth_result), 401
    
    user_id = auth_result['payload']['user_id']
    documentos = documentos_service.obtener_documentos(user_id)
    
    return jsonify({
        'success': True,
        'documentos': documentos
    })

@app.route('/api/documentos/<int:documento_id>', methods=['DELETE'])
def eliminar_documento_api(documento_id):
    """Elimina un documento, sus archivos firmados y sus QR registrados."""
    auth_header = request.headers.get('Authorization')
    if not DeclarativeValidators.is_valid_token(auth_header):
        return jsonify({'success': False, 'message': 'Token requerido'}), 401

    token = DeclarativeValidators.extract_token(auth_header)
    auth_result = auth.verify_token(token)
    if not auth_result['success']:
        return jsonify(auth_result), 401

    user_id = auth_result['payload']['user_id']
    rol = auth_result['payload'].get('rol', '')
    result = documentos_service.eliminar_documento(documento_id, user_id, rol)
    return jsonify(result), 200 if result.get('success') else 404

@app.route('/api/documentos/firmar', methods=['POST'])
def firmar_documento():
    """Firma un documento con biometria WebAuthn/OpenCV o contrasena."""
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'success': False, 'message': 'Token requerido'}), 401

    auth_result = auth.verify_token(token.replace('Bearer ', ''))
    if not auth_result['success']:
        return jsonify(auth_result), 401

    user_id = auth_result['payload']['user_id']
    data = request.get_json() or {}

    documento_id = data.get('documento_id')
    razon = data.get('razon', 'Firma digital de documento')
    ubicacion = data.get('ubicacion', '')
    connection = db.get_connection()
    if not connection:
        return jsonify({'success': False, 'message': 'Error de conexion'}), 500

    cursor = connection.cursor(dictionary=True)
    try:
        auth._ensure_user_signature_columns(cursor)
        connection.commit()
        cursor.execute("""
            SELECT Nombre, curp, cargo_firma, ubicacion_firma
            FROM Usuarios
            WHERE id_Usuario = %s
        """, (user_id,))
        perfil_firma = cursor.fetchone() or {}
    finally:
        cursor.close()
        connection.close()

    ubicacion = (ubicacion or perfil_firma.get('ubicacion_firma') or '').strip()
    datos_firmante = {
        'nombre': (data.get('firmante_nombre') or perfil_firma.get('Nombre') or '').strip(),
        'curp': (data.get('firmante_curp') or perfil_firma.get('curp') or '').strip().upper(),
        'cargo': (data.get('firmante_cargo') or perfil_firma.get('cargo_firma') or '').strip(),
        'ubicacion': ubicacion
    }

    if not documento_id:
        return jsonify({'success': False, 'message': 'ID de documento requerido'})

    if not all(datos_firmante.values()):
        return jsonify({'success': False, 'message': 'Nombre, CURP, cargo y ubicacion del firmante son requeridos'})

    if not re.match(r'^[A-Z0-9]{18}$', datos_firmante['curp']):
        return jsonify({'success': False, 'message': 'La CURP debe tener 18 caracteres alfanumericos'})

    password = data.get('password')
    if not password:
        return jsonify({'success': False, 'message': 'Contrasena requerida para firmar documento'})

    pw_result = auth.verify_password(user_id, password)
    if not pw_result['success']:
        return jsonify({'success': False, 'message': 'Contrasena incorrecta'})

    # Permite firmar en dos tipos de equipos:
    # 1) Con biometria/WebAuthn cuando el equipo tiene Windows Hello, huella, Face ID o llave de seguridad.
    # 2) Solo con contrasena cuando el equipo no tiene autenticador biometrico.
    metodo_verificacion = (data.get('metodo_verificacion') or '').strip().lower()
    if not metodo_verificacion:
        metodo_verificacion = 'fingerprint' if data.get('biometric_verified') else 'password'

    if metodo_verificacion not in ('fingerprint', 'password'):
        return jsonify({'success': False, 'message': 'Metodo de verificacion no valido'})

    if metodo_verificacion == 'fingerprint':
        connection = db.get_connection()
        if not connection:
            return jsonify({'success': False, 'message': 'Error de conexion'}), 500

        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT biometric_enabled FROM Usuarios
                WHERE id_Usuario = %s AND biometric_enabled = 1
            """, (user_id,))
            if not cursor.fetchone():
                return jsonify({
                    'success': False,
                    'message': 'No tienes biometria registrada. Firma con contrasena.'
                })

            credential_id = data.get('credential_id')
            if credential_id:
                cursor.execute("""
                    SELECT id FROM webauthn_credentials
                    WHERE user_id = %s AND credential_id = %s
                """, (user_id, credential_id))
                if not cursor.fetchone():
                    return jsonify({'success': False, 'message': 'Credencial biometrica no reconocida'})
            elif not data.get('biometric_verified'):
                return jsonify({'success': False, 'message': 'Credencial biometrica requerida para firmar'})
        finally:
            cursor.close()
            connection.close()

        fingerprint_image = None
        if 'fingerprint_image' in request.files:
            fingerprint_image = request.files['fingerprint_image'].read()
        elif data.get('fingerprint_image'):
            try:
                fingerprint_image = base64.b64decode(data['fingerprint_image'])
            except Exception:
                fingerprint_image = None

        if fingerprint_image:
            biometric_result = biometric.verify_fingerprint(user_id, fingerprint_image)
            if not biometric_result['success']:
                return jsonify({
                    'success': False,
                    'message': f'Verificacion biometrica fallida: {biometric_result["message"]}'
                })
    result = documentos_service.firmar_documento(
        documento_id, user_id, razon, ubicacion, datos_firmante,
        verification_base_url=get_public_base_url()
    )
    if result['success']:
        result['message'] = 'Documento firmado correctamente'

    return jsonify(result)

@app.route('/api/documentos-oficiales/generar', methods=['POST'])
def generar_documento_oficial_ia():
    """Genera redacción oficial con un motor local tipo IA."""
    auth_header = request.headers.get('Authorization')
    if not DeclarativeValidators.is_valid_token(auth_header):
        return jsonify({'success': False, 'message': 'Token requerido'}), 401

    token = DeclarativeValidators.extract_token(auth_header)
    auth_result = auth.verify_token(token)
    if not auth_result['success']:
        return jsonify(auth_result), 401

    data = request.get_json() or {}
    required = ['tipo']
    valid, message = DeclarativeValidators.has_required_fields(data, required)
    if not valid:
        return jsonify({'success': False, 'message': message}), 400

    tipo = data.get('tipo', 'Oficio')
    asunto = data.get('asunto', '').strip() or tipo
    destinatario = data.get('destinatario', '').strip() or 'A QUIEN CORRESPONDA'
    contexto = data.get('contexto', '').strip()
    alumno = data.get('alumno', '').strip()
    tutor = data.get('tutor', '').strip()
    fundamento = data.get('fundamento', '').strip()
    tono = data.get('tono', 'formal').strip().lower()

    aperturas = {
        'oficio escolar': 'Por medio del presente, la institución comunica formalmente lo siguiente:',
        'constancia de estudios': 'A quien corresponda, se hace constar la información académica siguiente:',
        'constancia de conducta': 'A quien corresponda, se hace constar la información de conducta siguiente:',
        'carta de recomendación escolar': 'Por medio de la presente, la institución emite la siguiente recomendación escolar:',
        'circular escolar': 'Se informa a la comunidad escolar lo siguiente:',
        'acta académica': 'En atención al asunto académico señalado, se deja asentado lo siguiente:',
        'oficio': 'Por medio del presente, se comunica formalmente lo siguiente:',
        'constancia': 'A quien corresponda, se hace constar lo siguiente:',
        'memorándum': 'Por este medio se informa para conocimiento y atención:',
        'circular': 'Se informa a las áreas correspondientes lo siguiente:',
        'acta': 'En atención al asunto señalado, se deja asentado lo siguiente:'
    }
    cierre = {
        'formal': 'Sin otro particular, quedo atento a cualquier aclaración o seguimiento que corresponda.',
        'directo': 'Se solicita tomar conocimiento y realizar las acciones correspondientes.',
        'cordial': 'Agradezco de antemano la atención brindada al presente documento.'
    }.get(tono, 'Sin otro particular, quedo atento a cualquier aclaración o seguimiento que corresponda.')

    sujeto = alumno or 'el alumno indicado'
    referencia_tutor = f' a solicitud de {tutor}' if tutor else ''
    tipo_lower = tipo.lower()

    if 'constancia de estudios' in tipo_lower:
        cuerpo = f"""
        {aperturas['constancia de estudios']}

        Por medio de la presente se hace constar que {sujeto} se encuentra inscrito(a) en esta institución educativa durante el ciclo escolar vigente, conforme a los registros académicos y administrativos disponibles en el área de control escolar.

        {contexto if contexto else 'La información asentada se emite para acreditar su situación académica actual.'}

        La presente constancia se expide{referencia_tutor} para los fines escolares, administrativos o personales que resulten procedentes ante {destinatario}.
        """
    elif 'constancia de conducta' in tipo_lower:
        cuerpo = f"""
        {aperturas['constancia de conducta']}

        Por medio de la presente se hace constar que {sujeto} cuenta con registro de conducta revisado por esta institución educativa, conforme a la información disponible en su expediente escolar.

        {contexto if contexto else 'A la fecha de emisión, no se advierten observaciones adicionales que impidan extender la presente constancia para trámite escolar.'}

        La constancia se expide{referencia_tutor} en relación con el asunto "{asunto}" y para presentarse ante {destinatario}.
        """
    elif 'carta de recomendación' in tipo_lower:
        cuerpo = f"""
        {aperturas['carta de recomendación escolar']}

        La institución extiende la presente recomendación en favor de {sujeto}, quien ha formado parte de la comunidad escolar y ha mantenido participación dentro de las actividades académicas correspondientes.

        {contexto if contexto else 'Con base en la información disponible, se recomienda considerar favorablemente a la persona mencionada para los fines escolares o administrativos que correspondan.'}

        Se expide la presente{referencia_tutor} para presentarse ante {destinatario}.
        """
    elif 'circular' in tipo_lower:
        cuerpo = f"""
        {aperturas.get(tipo_lower, aperturas['circular escolar'])}

        {contexto}

        Se solicita a la comunidad escolar tomar conocimiento de la información anterior y atender las indicaciones correspondientes en los tiempos establecidos.
        """
    elif 'acta' in tipo_lower:
        cuerpo = f"""
        {aperturas.get(tipo_lower, aperturas['acta académica'])}

        En la fecha señalada se registra el asunto "{asunto}" relacionado con {sujeto}. Se deja constancia de los hechos, acuerdos o información académica siguiente:

        {contexto}

        La presente acta se integra para control escolar y seguimiento administrativo.
        """
    else:
        detalle = contexto or f'Se atiende la solicitud relacionada con {sujeto}.'
        cuerpo = f"""
        {aperturas.get(tipo_lower, aperturas['oficio escolar'])}

        Con fundamento en las atribuciones administrativas de la institución educativa, se informa lo siguiente:

        {detalle}

        En relación con el asunto "{asunto}", se solicita a {destinatario} considerar la información anterior para los fines académicos, administrativos y de control escolar que resulten procedentes.
        """
    if fundamento:
        cuerpo += f"\n\nEste documento se emite con base en la siguiente referencia: {fundamento}."
    cuerpo += f"\n\n{cierre}"

    contenido = '\n'.join(line.strip() for line in textwrap.dedent(cuerpo).strip().splitlines())
    contenido = re.sub(r'\n{3,}', '\n\n', contenido)

    return jsonify({
        'success': True,
        'contenido': contenido,
        'message': 'Documento generado automáticamente'
    })
@app.route('/api/documentos/firmados', methods=['GET'])
def obtener_documentos_firmados():
    """Obtiene los documentos firmados"""
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'success': False, 'message': 'Token requerido'}), 401
    
    auth_result = auth.verify_token(token.replace('Bearer ', ''))
    if not auth_result['success']:
        return jsonify(auth_result), 401
    
    user_id = auth_result['payload']['user_id']
    rol = auth_result['payload'].get('rol', '')
    documentos_firmados = documentos_service.obtener_documentos_firmados(user_id, rol)
    
    return jsonify({
        'success': True,
        'documentos': documentos_firmados
    })

@app.route('/api/documentos/<int:documento_id>/descargar-firmado', methods=['GET'])
def descargar_documento_firmado(documento_id):
    """Descarga la copia del documento con constancia QR de firma."""
    auth_header = request.headers.get('Authorization')
    if not DeclarativeValidators.is_valid_token(auth_header):
        return jsonify({'success': False, 'message': 'Token requerido'}), 401

    token = DeclarativeValidators.extract_token(auth_header)
    auth_result = auth.verify_token(token)
    if not auth_result['success']:
        return jsonify(auth_result), 401

    user_id = auth_result['payload']['user_id']
    documento = documentos_service.obtener_documento_firmado_path(documento_id, user_id)
    if not documento:
        return jsonify({'success': False, 'message': 'Documento firmado no encontrado'}), 404

    ruta = documento['ruta_archivo_firmado']
    extension = os.path.splitext(ruta)[1].lower()
    titulo = secure_filename(documento.get('titulo') or f'documento_{documento_id}') or f'documento_{documento_id}'
    return send_file(ruta, as_attachment=True, download_name=f'{titulo}_firmado{extension}')

# ========== AUDITORÃA Y LOGS ==========

# FUNCIÃ“N 14: obtener_logs_accesos (declarativa)
@app.route('/api/admin/logs/accesos', methods=['GET'])
def obtener_logs_accesos():
    """Obtener logs de acceso - VersiÃ³n declarativa"""
    auth_header = request.headers.get('Authorization')
    if not DeclarativeValidators.is_valid_token(auth_header):
        return jsonify({'success': False, 'message': 'Token requerido'}), 401
    
    token = DeclarativeValidators.extract_token(auth_header)
    auth_result = auth.verify_token(token)
    if not auth_result['success']:
        return jsonify(auth_result), 401
    
    user_id = auth_result['payload']['user_id']
    
    logs = audit_log.obtener_logs_usuarios(user_id, limit=100)
    
    if not logs:
        return jsonify({
            'success': False,
            'message': 'Acceso denegado. Solo Directors pueden ver los logs.',
            'logs': []
        }), 403
    
    return jsonify({
        'success': True,
        'logs': logs,
        'total': len(logs)
    })

# FUNCIÃ“N 13: listar_documentos_para_firmar (declarativa)
@app.route('/api/documentos/listar-para-firmar', methods=['GET'])
def listar_documentos_para_firmar():
    """Lista documentos pendientes - VersiÃ³n declarativa"""
    auth_header = request.headers.get('Authorization')
    if not DeclarativeValidators.is_valid_token(auth_header):
        return jsonify({'success': False, 'message': 'Token requerido'}), 401
    
    token = DeclarativeValidators.extract_token(auth_header)
    auth_result = auth.verify_token(token)
    if not auth_result['success']:
        return jsonify(auth_result), 401
    
    user_id = auth_result['payload']['user_id']
    
    connection = db.get_connection()
    if not connection:
        return jsonify({'success': False, 'message': 'Error de conexiÃ³n'}), 500
    
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT id, titulo, descripcion, tamaÃ±o, estado, fecha_subida, fecha_firma
            FROM Documentos_PDF
            WHERE usuario_id = %s
            ORDER BY fecha_subida DESC
        """, (user_id,))
        
        documentos = cursor.fetchall()
        
        # TransformaciÃ³n declarativa usando el formateador
        return jsonify(DeclarativeResponseBuilder.with_documents(documentos, "Documentos pendientes obtenidos"))
    finally:
        cursor.close()
        connection.close()

if __name__ == '__main__':
    print(" Iniciando servidor de Firma Digital...")
    print(" URL: http://localhost:5000")
    print(" Sistema de recuperaciÃ³n de contraseÃ±a activo")
    print(" AutenticaciÃ³n biomÃ©trica configurada")
    print(" Sistema de firmas RSA listo")
    print(" Base de datos: MySQL")
    app.run(host='0.0.0.0', port=5000, debug=True)
