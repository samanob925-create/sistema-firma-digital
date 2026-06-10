import os

class Config:
    SECRET_KEY = 'clave_secreta_muy_segura_para_jwt_firma_digital_2024'
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = ''
    MYSQL_DB = 'base_firma'
    UPLOAD_FOLDER = 'uploads'
    BIOMETRIC_FOLDER = 'biometric_templates'
    RECAPTCHA_SITE_KEY = '6LedVvkrAAAAAGbteljCgmVHKi0Jc_pbzC_Fnv7T'
    RECAPTCHA_SECRET_KEY = '6LedVvkrAAAAABgjd0jBcFPHDaros65yZbbRdGZt'
    
    # Configuración de Email
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'colorado3oscar@gmail.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'Bocadin150')
    MAIL_FROM = os.environ.get('MAIL_FROM', f'Firma Digital <{MAIL_USERNAME}>')
    # En modo desarrollo, permite que el token de recuperación se incluya en la respuesta
    # Útil para testing local. Poner False en producción.
    MAIL_FORCE_SHOW_TOKEN = True
    # Si quieres que el QR sea publico fuera de tu red local, coloca aqui una URL como ngrok o dominio.
    PUBLIC_BASE_URL = os.environ.get('PUBLIC_BASE_URL', '')
    
    @staticmethod
    def init_app(app):
        # Crear directorios necesarios
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(os.path.join(Config.UPLOAD_FOLDER, 'firmados'), exist_ok=True)
        os.makedirs(os.path.join(Config.UPLOAD_FOLDER, 'documentos'), exist_ok=True)
        os.makedirs(Config.BIOMETRIC_FOLDER, exist_ok=True)
