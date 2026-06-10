"""Módulo para enviar emails"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config.config import Config

class EmailService:
    """Servicio para enviar emails"""
    
    @staticmethod
    def send_recovery_token(email, token, user_name):
        """Envía el token de recuperación por email"""
        try:
            subject = "Recuperación de Contraseña - Firma Digital"
            
            # HTML del email
            html_body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px;">
                    <div style="background-color: white; border-radius: 8px; padding: 30px; max-width: 500px; margin: 0 auto;">
                        <h2 style="color: #6C63FF; text-align: center;"> Recuperación de Contraseña</h2>
                        
                        <p>Hola <strong>{user_name}</strong>,</p>
                        
                        <p>Recibimos una solicitud para recuperar tu contraseña. Usa el siguiente código para restablecer tu acceso:</p>
                        
                        <div style="background-color: #f0f2f5; border-left: 4px solid #6C63FF; padding: 15px; margin: 20px 0; border-radius: 4px;">
                            <p style="margin: 0; color: #333;">
                                <strong>Código de Recuperación:</strong><br>
                                <code style="font-size: 20px; color: #6C63FF; font-weight: bold; letter-spacing: 2px;">
                                    {token}
                                </code>
                            </p>
                        </div>
                        
                        <p style="color: #666; font-size: 14px;">
                            <strong> Este código expira en 1 hora.</strong><br>
                            Si no solicitaste este cambio, ignora este email.
                        </p>
                        
                        <div style="border-top: 1px solid #eee; margin-top: 20px; padding-top: 15px; font-size: 12px; color: #999;">
                            <p>Sistema de Firma Digital Segura<br>
                            Este es un email automático, no respondas a este mensaje.</p>
                        </div>
                    </div>
                </body>
            </html>
            """
            
            # Crear mensaje
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = Config.MAIL_FROM
            msg['To'] = email
            
            # Agregar versión de texto plano
            text_body = f"""
Recuperación de Contraseña - Firma Digital

Hola {user_name},

Tu código de recuperación es: {token}

Este código expira en 1 hora.

Sistema de Firma Digital Segura
            """
            
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            if not all([Config.MAIL_SERVER, Config.MAIL_USERNAME, Config.MAIL_PASSWORD, Config.MAIL_FROM]):
                print("Correo no configurado; se usara el codigo local de recuperacion.")
                return False

            # Enviar email
            print(f"Intentando enviar email a {email}...")
            try:
                with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT, timeout=3) as server:
                    server.starttls()
                    server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
                    server.send_message(msg)
                print(f" Email enviado exitosamente a {email}")
                return True
            except smtplib.SMTPAuthenticationError:
                print(f" Error de autenticación SMTP. Verifica credenciales en config.py")
                return False
            except smtplib.SMTPException as smtp_e:
                print(f" Error SMTP: {str(smtp_e)}")
                return False
            
        except Exception as e:
            print(f" Error enviando email: {type(e).__name__} - {str(e)}")
            return False
    
    @staticmethod
    def send_biometric_confirmation(email, user_name):
        """Envía confirmación cuando la huella se registra exitosamente"""
        try:
            subject = "Huella Digital Registrada - Firma Digital"
            
            html_body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px;">
                    <div style="background-color: white; border-radius: 8px; padding: 30px; max-width: 500px; margin: 0 auto;">
                        <h2 style="color: #4CAF50; text-align: center;"> Huella Digital Registrada</h2>
                        
                        <p>Hola <strong>{user_name}</strong>,</p>
                        
                        <p>Tu huella dactilar ha sido registrada exitosamente en el sistema.</p>
                        
                        <div style="background-color: #e8f5e9; border-left: 4px solid #4CAF50; padding: 15px; margin: 20px 0; border-radius: 4px;">
                            <p style="margin: 0; color: #2e7d32;">
                                ✓ Ya puedes iniciar sesión usando tu huella digital en el sensor de tu dispositivo.
                            </p>
                        </div>
                        
                        <p style="color: #666; font-size: 14px;">
                            Si no realizaste este registro, contacta al administrador inmediatamente.
                        </p>
                    </div>
                </body>
            </html>
            """
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = Config.MAIL_FROM
            msg['To'] = email
            
            text_body = f"""
            Huella Digital Registrada
            
            Hola {user_name},
            
            Tu huella dactilar ha sido registrada exitosamente.
            Ya puedes iniciar sesión usando el sensor biométrico.
            """
            
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT) as server:
                server.starttls()
                server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
                server.send_message(msg)
            
            print(f" Confirmación enviada a {email}")
            return True
            
        except Exception as e:
            print(f" Error enviando email: {e}")
            return False
