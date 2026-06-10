"""Módulo para gestionar documentos PDF y firmas"""
import os
import hashlib
import rsa
import base64
import io
import secrets
import textwrap
from datetime import datetime
from models.database import Database
import qrcode
from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from models.certificacion_archivos import CertificacionArchivos

class DocumentosService:
    """Servicio para gestionar documentos y firmas"""
    
    def __init__(self):
        self.db = Database()
        self.upload_folder = 'uploads/documentos'
        os.makedirs(self.upload_folder, exist_ok=True)
        self.certificador = CertificacionArchivos()
    
    def subir_documento(self, titulo, usuario_id, archivo, descripcion=''):
        """Sube un documento PDF"""
        connection = self.db.get_connection()
        cursor = connection.cursor()
        
        try:
            # Crear tabla si no existe
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Documentos_PDF (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    titulo VARCHAR(255) NOT NULL,
                    descripcion TEXT,
                    usuario_id INT NOT NULL,
                    ruta_archivo VARCHAR(500) NOT NULL,
                    hash_archivo VARCHAR(255) NOT NULL,
                    tamaño INT,
                    estado ENUM('Pendiente', 'Firmado') DEFAULT 'Pendiente',
                    fecha_subida TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    fecha_firma TIMESTAMP NULL,
                    FOREIGN KEY (usuario_id) REFERENCES Usuarios(id_Usuario),
                    KEY (estado)
                )
            """)
            connection.commit()
            
            # Generar nombre único para el archivo
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{usuario_id}_{timestamp}_{archivo.filename}"
            filepath = os.path.join(self.upload_folder, filename)
            
            # Guardar archivo
            archivo.save(filepath)
            
            # Calcular hash del archivo
            file_hash = self._calcular_hash_archivo(filepath)
            file_size = os.path.getsize(filepath)
            
            # Insertar en BD
            cursor.execute("""
                INSERT INTO Documentos_PDF 
                (titulo, descripcion, usuario_id, ruta_archivo, hash_archivo, tamaño)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (titulo, descripcion, usuario_id, filepath, file_hash, file_size))
            
            connection.commit()
            doc_id = cursor.lastrowid
            
            certificacion = self.certificador.certificar_archivo(
                ruta_archivo=filepath,
                usuario_id=usuario_id,
                documento_id=doc_id,
                origen="archivo_subido_para_firma"
            )
            
            return {
                'success': True,
                'message': 'Documento subido exitosamente',
                'documento_id': doc_id,
                'filename': filename,
                'hash_sha256': file_hash,
                'certificacion': certificacion
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
        finally:
            cursor.close()
            connection.close()
    
    def obtener_documentos(self, usuario_id):
        """Obtiene los documentos del usuario"""
        connection = self.db.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        try:
            cursor.execute("""
                SELECT id, titulo, descripcion, estado, tamaño, fecha_subida, fecha_firma
                FROM Documentos_PDF
                WHERE usuario_id = %s
                ORDER BY fecha_subida DESC
            """, (usuario_id,))
            
            return cursor.fetchall()
            
        finally:
            cursor.close()
            connection.close()
    
    def firmar_documento(self, documento_id, usuario_id, razon, ubicacion='', datos_firmante=None,
                         verification_base_url=None):
        """Registra la firma de un documento"""
        datos_firmante = datos_firmante or {}
        connection = self.db.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        try:
            # Crear tabla de firmas si no existe
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Firmas_Documentos (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    documento_id INT NOT NULL,
                    usuario_id INT NOT NULL,
                    razon VARCHAR(255),
                    ubicacion VARCHAR(255),
                    clave_publica LONGTEXT,
                    hash_documento VARCHAR(255),
                    firma_digital LONGTEXT,
                    codigo_verificacion VARCHAR(64),
                    qr_payload TEXT,
                    qr_code LONGTEXT,
                    firmante_nombre VARCHAR(255),
                    firmante_curp VARCHAR(18),
                    firmante_cargo VARCHAR(150),
                    fecha_firma TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    algoritmo_firma VARCHAR(50) DEFAULT 'SHA256-RSA',
                    FOREIGN KEY (documento_id) REFERENCES Documentos_PDF(id),
                    FOREIGN KEY (usuario_id) REFERENCES Usuarios(id_Usuario)
                )
            """)
            self._ensure_signature_columns(cursor)
            self._ensure_document_columns(cursor)
            connection.commit()
            
            # Obtener documento para calcular hash
            cursor.execute("""
                SELECT ruta_archivo, hash_archivo, titulo FROM Documentos_PDF 
                WHERE id = %s AND usuario_id = %s
            """, (documento_id, usuario_id))
            
            documento = cursor.fetchone()
            if not documento:
                return {'success': False, 'message': 'Documento no encontrado'}

            cursor.execute("""
                SELECT Nombre, Apellido_P, Apellido_M, Email, rol
                FROM Usuarios
                WHERE id_Usuario = %s
            """, (usuario_id,))
            firmante = cursor.fetchone() or {}
            firmante['Nombre_Completo_Firma'] = datos_firmante.get('nombre') or self._nombre_firmante(firmante)
            firmante['CURP'] = datos_firmante.get('curp', '')
            firmante['Cargo_Firma'] = datos_firmante.get('cargo') or firmante.get('rol', '')
            
            # Generar par de claves RSA
            pubkey, privkey = rsa.newkeys(2048)
            clave_publica_pem = pubkey.save_pkcs1().decode('utf-8')
            
            # Calcular hash del contenido del documento
            hash_documento = documento['hash_archivo']  # Ya tenemos el hash del archivo
            
            # Generar firma (usando el hash del documento)
            firma_digital = rsa.sign(hash_documento.encode(), privkey, 'SHA-256')
            firma_base64 = base64.b64encode(firma_digital).decode('utf-8')
            codigo_verificacion = secrets.token_urlsafe(18)
            fecha_firma = datetime.now()
            qr_payload = self._crear_qr_payload(
                documento_id=documento_id,
                titulo=documento.get('titulo', ''),
                firmante=firmante,
                razon=razon,
                ubicacion=ubicacion,
                hash_documento=hash_documento,
                codigo_verificacion=codigo_verificacion,
                fecha_firma=fecha_firma,
                verification_base_url=verification_base_url
            )
            qr_code = self._generar_qr_data_url(qr_payload)
            ruta_firmada = self._generar_documento_firmado(
                documento=documento,
                documento_id=documento_id,
                firmante=firmante,
                razon=razon,
                ubicacion=ubicacion,
                hash_documento=hash_documento,
                codigo_verificacion=codigo_verificacion,
                qr_code=qr_code,
                fecha_firma=fecha_firma
            )
            hash_archivo_firmado = self._calcular_hash_archivo(ruta_firmada) if ruta_firmada else None
            
            certificacion_firmado = None
            if ruta_firmada:
                certificacion_firmado = self.certificador.certificar_archivo(
                    ruta_archivo=ruta_firmada,
                    usuario_id=usuario_id,
                    documento_id=documento_id,
                    origen="documento_firmado_generado_por_el_sistema"
                )
            
            # Insertar firma con claves y hash
            cursor.execute("""
                INSERT INTO Firmas_Documentos
                (documento_id, usuario_id, razon, ubicacion, clave_publica, hash_documento, firma_digital,
                 codigo_verificacion, qr_payload, qr_code, firmante_nombre, firmante_curp, firmante_cargo)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                documento_id, usuario_id, razon, ubicacion, clave_publica_pem, hash_documento,
                firma_base64, codigo_verificacion, qr_payload, qr_code,
                firmante['Nombre_Completo_Firma'], firmante['CURP'], firmante['Cargo_Firma']
            ))
            
            # Actualizar estado del documento
            cursor.execute("""
                UPDATE Documentos_PDF
                SET estado = 'Firmado',
                    fecha_firma = NOW(),
                    ruta_archivo_firmado = %s,
                    hash_archivo_firmado = %s
                WHERE id = %s AND usuario_id = %s
            """, (ruta_firmada, hash_archivo_firmado, documento_id, usuario_id))
            
            connection.commit()
            firma_id = cursor.lastrowid
            
            return {
                'success': True,
                'message': ' Documento firmado exitosamente',
                'firma_id': firma_id,
                'clave_publica': clave_publica_pem,
                'hash_documento': hash_documento,
                'firma_digital': firma_base64,
                'algoritmo': 'SHA256-RSA',
                'codigo_verificacion': codigo_verificacion,
                'qr_payload': qr_payload,
                'qr_code': qr_code,
                'ruta_archivo_firmado': ruta_firmada,
                'certificacion_firmado': certificacion_firmado
            }
            
        except Exception as e:
            connection.rollback()
            return {'success': False, 'message': str(e)}
        finally:
            cursor.close()
            connection.close()
    
    def obtener_documentos_firmados(self, usuario_id, rol=''):
        """Obtiene los documentos firmados por el usuario"""
        connection = self.db.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        try:
            self._ensure_document_columns(cursor)
            self._ensure_signature_columns(cursor)
            connection.commit()
            es_director = (rol or '').strip().lower() == 'director'
            filtro = "" if es_director else "WHERE dp.usuario_id = %s"
            params = () if es_director else (usuario_id,)

            cursor.execute(f"""
                SELECT 
                    dp.id, dp.titulo, dp.estado,
                    u.Nombre as firmado_por,
                    fd.fecha_firma,
                    fd.algoritmo_firma,
                    fd.codigo_verificacion,
                    fd.firmante_nombre,
                    fd.firmante_curp,
                    fd.firmante_cargo,
                    fd.qr_code,
                    dp.ruta_archivo_firmado
                FROM Documentos_PDF dp
                LEFT JOIN Firmas_Documentos fd ON dp.id = fd.documento_id
                LEFT JOIN Usuarios u ON fd.usuario_id = u.id_Usuario
                {filtro}
                {"AND" if filtro else "WHERE"} dp.estado = 'Firmado'
                ORDER BY fd.fecha_firma DESC
            """, params)
            
            return cursor.fetchall()
            
        finally:
            cursor.close()
            connection.close()

    def eliminar_documento(self, documento_id, usuario_id, rol=''):
        """Elimina el registro, firmas, QR y archivos fisicos asociados."""
        connection = self.db.get_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            self._ensure_document_columns(cursor)
            connection.commit()

            es_director = (rol or '').strip().lower() == 'director'
            if es_director:
                cursor.execute("""
                    SELECT id, ruta_archivo, ruta_archivo_firmado
                    FROM Documentos_PDF
                    WHERE id = %s
                """, (documento_id,))
            else:
                cursor.execute("""
                    SELECT id, ruta_archivo, ruta_archivo_firmado
                    FROM Documentos_PDF
                    WHERE id = %s AND usuario_id = %s
                """, (documento_id, usuario_id))

            documento = cursor.fetchone()
            if not documento:
                return {'success': False, 'message': 'Documento no encontrado'}

            rutas = [
                documento.get('ruta_archivo'),
                documento.get('ruta_archivo_firmado')
            ]

            cursor.execute("DELETE FROM Firmas_Documentos WHERE documento_id = %s", (documento_id,))
            firmas_eliminadas = cursor.rowcount
            cursor.execute("DELETE FROM Documentos_PDF WHERE id = %s", (documento_id,))
            connection.commit()

            archivos_eliminados = 0
            for ruta in rutas:
                if ruta and os.path.exists(ruta):
                    try:
                        os.remove(ruta)
                        archivos_eliminados += 1
                    except OSError:
                        pass

            return {
                'success': True,
                'message': 'Documento eliminado correctamente',
                'firmas_eliminadas': firmas_eliminadas,
                'archivos_eliminados': archivos_eliminados
            }
        except Exception as e:
            connection.rollback()
            return {'success': False, 'message': str(e)}
        finally:
            cursor.close()
            connection.close()
    
    @staticmethod
    def _calcular_hash_archivo(filepath):
        """Calcula el hash SHA256 de un archivo"""
        sha256_hash = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    @staticmethod
    def _generar_qr_data_url(payload):
        """Genera un QR PNG en base64 para incrustarlo directo en el frontend."""
        qr = qrcode.QRCode(version=1, box_size=8, border=3)
        qr.add_data(payload)
        qr.make(fit=True)
        image = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("utf-8")

    def obtener_documento_firmado_path(self, documento_id, usuario_id):
        """Devuelve la ruta del PDF firmado si pertenece al usuario."""
        connection = self.db.get_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            self._ensure_document_columns(cursor)
            connection.commit()
            cursor.execute("""
                SELECT titulo, ruta_archivo_firmado
                FROM Documentos_PDF
                WHERE id = %s AND usuario_id = %s AND estado = 'Firmado'
            """, (documento_id, usuario_id))
            documento = cursor.fetchone()
            if not documento or not documento.get('ruta_archivo_firmado'):
                return None
            if not os.path.exists(documento['ruta_archivo_firmado']):
                return None
            return documento
        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def _nombre_firmante(firmante):
        if firmante.get('Nombre_Completo_Firma'):
            return str(firmante.get('Nombre_Completo_Firma')).strip()
        partes = [
            firmante.get('Nombre', ''),
            firmante.get('Apellido_P', ''),
            firmante.get('Apellido_M', '')
        ]
        return ' '.join(str(parte).strip() for parte in partes if parte).strip() or 'Firmante'

    def _crear_qr_payload(self, documento_id, titulo, firmante, razon, ubicacion, hash_documento,
                          codigo_verificacion, fecha_firma, verification_base_url=None):
        """URL publica que abre la constancia de verificacion."""
        if verification_base_url:
            return f'{verification_base_url}/verificar/{codigo_verificacion}'

        nombre = self._nombre_firmante(firmante)
        return '\n'.join([
            'CONSTANCIA DE FIRMA DIGITAL ESCOLAR',
            f'Documento: {titulo or documento_id}',
            f'ID: {documento_id}',
            f'Firmado por: {nombre}',
            f'CURP: {firmante.get("CURP", "No capturada")}',
            f'Cargo: {firmante.get("Cargo_Firma") or firmante.get("rol", "No capturado")}',
            f'Ubicacion: {ubicacion or "No especificada"}',
            f'Fecha: {fecha_firma.strftime("%Y-%m-%d %H:%M:%S")}',
            f'Verificacion: {codigo_verificacion}',
            f'Hash SHA256: {hash_documento}',
            'Algoritmo: SHA256-RSA'
        ])

    def _generar_documento_firmado(self, documento, documento_id, firmante, razon, ubicacion,
                                   hash_documento, codigo_verificacion, qr_code, fecha_firma):
        """Crea una copia PDF con una pagina final de constancia y QR."""
        ruta_original = documento.get('ruta_archivo')
        if not ruta_original or not os.path.exists(ruta_original):
            return None

        extension = os.path.splitext(ruta_original)[1].lower()
        if extension != '.pdf':
            return self._generar_constancia_pdf(
                documento, documento_id, firmante, razon, ubicacion,
                hash_documento, codigo_verificacion, qr_code, fecha_firma
            )

        signed_folder = os.path.join(self.upload_folder, 'firmados')
        os.makedirs(signed_folder, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(ruta_original))[0]
        ruta_firmada = os.path.join(signed_folder, f'{base_name}_firmado_{documento_id}.pdf')
        reader = PdfReader(ruta_original)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        firma_reader = PdfReader(self._crear_pagina_qr_firma_pdf(qr_code))
        writer.add_page(firma_reader.pages[0])

        with open(ruta_firmada, 'wb') as output:
            writer.write(output)

        return ruta_firmada

    def _crear_pagina_qr_firma_pdf(self, qr_code):
        """Pagina final de firma con QR, sin datos visibles."""
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        qr_bytes = base64.b64decode(qr_code.split(',', 1)[1])
        qr_image = ImageReader(io.BytesIO(qr_bytes))

        qr_size = 190
        x = (width - qr_size) / 2
        y = (height - qr_size) / 2
        pdf.setStrokeColor(colors.HexColor('#111827'))
        pdf.setLineWidth(1)
        pdf.rect(x - 12, y - 12, qr_size + 24, qr_size + 24, stroke=1, fill=0)
        pdf.drawImage(qr_image, x, y, width=qr_size, height=qr_size, mask='auto')
        pdf.showPage()
        pdf.save()
        buffer.seek(0)
        return buffer

    def _crear_pagina_sello_pdf(self, documento, documento_id, firmante, razon, ubicacion,
                                hash_documento, codigo_verificacion, qr_code, fecha_firma):
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        nombre = self._nombre_firmante(firmante)

        pdf.setTitle('Constancia de firma digital')
        pdf.setFillColor(colors.HexColor('#1f2937'))
        pdf.setFont('Helvetica-Bold', 16)
        pdf.drawString(50, height - 60, 'Constancia de firma digital escolar')

        pdf.setStrokeColor(colors.HexColor('#2563eb'))
        pdf.setLineWidth(2)
        pdf.line(50, height - 75, width - 50, height - 75)

        pdf.setFillColor(colors.HexColor('#374151'))
        pdf.setFont('Helvetica', 9)
        pdf.drawString(50, height - 93, 'Ejemplo de validacion: al escanear el QR se muestran los datos del documento, firmante, fecha, codigo y hash SHA256.')

        y = height - 128
        lineas = [
            ('Documento', documento.get('titulo') or str(documento_id)),
            ('ID documento', str(documento_id)),
            ('Firmante', nombre),
            ('CURP', firmante.get('CURP', '')),
            ('Cargo', firmante.get('Cargo_Firma') or firmante.get('rol', '')),
            ('Ubicacion de firma', ubicacion or 'No especificada'),
            ('Correo', firmante.get('Email', '')),
            ('Fecha de firma', fecha_firma.strftime('%Y-%m-%d %H:%M:%S')),
            ('Razon', razon or 'Firma digital de documento'),
            ('Algoritmo', 'SHA256-RSA'),
            ('Codigo de verificacion', codigo_verificacion),
            ('Hash SHA256 original', hash_documento),
        ]

        pdf.setFont('Helvetica', 10)
        for etiqueta, valor in lineas:
            pdf.setFillColor(colors.HexColor('#111827'))
            pdf.setFont('Helvetica-Bold', 10)
            pdf.drawString(50, y, f'{etiqueta}:')
            pdf.setFont('Helvetica', 10)
            texto = str(valor or '')
            if etiqueta.startswith('Hash'):
                texto = texto[:64]
            pdf.drawString(180, y, texto)
            y -= 22

        qr_bytes = base64.b64decode(qr_code.split(',', 1)[1])
        qr_image = ImageReader(io.BytesIO(qr_bytes))
        pdf.drawImage(qr_image, width - 225, height - 310, width=165, height=165, mask='auto')
        pdf.setFont('Helvetica-Bold', 9)
        pdf.drawCentredString(width - 142, height - 326, 'Escanea para ver datos de firma')

        pdf.setFillColor(colors.HexColor('#4b5563'))
        pdf.setFont('Helvetica', 8)
        pdf.drawString(50, 55, 'Este sello confirma que el documento fue firmado digitalmente dentro del sistema.')
        pdf.drawString(50, 42, 'La validez criptografica se basa en el hash SHA256 y firma RSA registrados en la base de datos.')
        pdf.showPage()
        pdf.save()
        buffer.seek(0)
        return buffer

    def _generar_constancia_pdf(self, documento, documento_id, firmante, razon, ubicacion,
                                hash_documento, codigo_verificacion, qr_code, fecha_firma):
        signed_folder = os.path.join(self.upload_folder, 'firmados')
        os.makedirs(signed_folder, exist_ok=True)
        ruta_firmada = os.path.join(signed_folder, f'documento_{documento_id}_firmado.pdf')
        documento_pdf = self._crear_documento_base_pdf(documento, documento_id, firmante, qr_code)
        writer = PdfWriter()
        documento_reader = PdfReader(documento_pdf)
        for page in documento_reader.pages:
            writer.add_page(page)
        with open(ruta_firmada, 'wb') as output:
            writer.write(output)
        return ruta_firmada

    def _crear_documento_base_pdf(self, documento, documento_id, firmante, qr_code):
        """Convierte una constancia de texto en PDF y coloca el QR en la firma."""
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        titulo = documento.get('titulo') or f'Documento {documento_id}'
        contenido = self._limpiar_bloque_firma(self._leer_contenido_texto(documento.get('ruta_archivo')))

        pdf.setTitle(titulo)
        qr_size = 118
        bottom_margin = 42
        qr_y = bottom_margin + 16
        text_bottom = qr_y + qr_size + 24
        y = height - 52
        pdf.setFillColor(colors.HexColor('#1f2937'))
        pdf.setFont('Helvetica-Bold', 13)
        pdf.drawCentredString(width / 2, y, titulo[:90])
        y -= 20
        pdf.setStrokeColor(colors.HexColor('#8f1d2c'))
        pdf.setLineWidth(1.5)
        pdf.line(54, y, width - 54, y)
        y -= 24

        parrafos = contenido.splitlines() or ['Documento generado para firma digital.']
        font_size = 10
        line_height = 13
        wrapped = []
        while font_size >= 7:
            max_chars = max(72, int(92 * (10 / font_size)))
            wrapped = []
            for parrafo in parrafos:
                lineas = textwrap.wrap(parrafo, width=max_chars) or ['']
                wrapped.extend(lineas)
                wrapped.append('')
            available_lines = int((y - text_bottom) / line_height)
            if len(wrapped) <= available_lines or font_size == 7:
                break
            font_size -= 1
            line_height = font_size + 3

        pdf.setFillColor(colors.HexColor('#111827'))
        pdf.setFont('Helvetica', font_size)
        available_lines = max(1, int((y - text_bottom) / line_height))
        for linea in wrapped[:available_lines]:
            pdf.drawString(60, y, linea)
            y -= line_height

        qr_bytes = base64.b64decode(qr_code.split(',', 1)[1])
        qr_image = ImageReader(io.BytesIO(qr_bytes))
        pdf.drawImage(qr_image, (width - qr_size) / 2, qr_y, width=qr_size, height=qr_size, mask='auto')

        pdf.showPage()
        pdf.save()
        buffer.seek(0)
        return buffer

    @staticmethod
    def _limpiar_bloque_firma(contenido):
        """Quita lineas de firma textual para reemplazarlas por el QR."""
        lineas = contenido.splitlines()
        marcadores = ('atentamente', 'firma', 'firmante')
        corte = None
        for index, linea in enumerate(lineas):
            normalizada = linea.strip().lower().strip(':')
            if normalizada in marcadores or normalizada.startswith('atentamente'):
                corte = index
                break
        if corte is None:
            return contenido.strip()
        return '\n'.join(lineas[:corte]).strip() or contenido.strip()

    @staticmethod
    def _leer_contenido_texto(ruta_archivo):
        if not ruta_archivo or not os.path.exists(ruta_archivo):
            return 'Documento generado para firma digital.'
        for encoding in ('utf-8', 'latin-1'):
            try:
                with open(ruta_archivo, 'r', encoding=encoding) as archivo:
                    return archivo.read().strip() or 'Documento generado para firma digital.'
            except UnicodeDecodeError:
                continue
            except OSError:
                break
        return 'El archivo original no es PDF. Se agrega esta constancia para conservar su registro de firma.'

    def obtener_constancia_por_codigo(self, codigo_verificacion):
        """Obtiene datos publicos de una firma por codigo de verificacion."""
        return self.buscar_firma_por_clave(codigo_verificacion, solo_codigo=True)

    def buscar_firma_por_clave(self, clave, solo_codigo=False):
        """Busca una firma por codigo, firma digital, hash o clave publica."""
        connection = self.db.get_connection()
        if not connection:
            return {'success': False, 'message': 'Error de conexion'}

        cursor = connection.cursor(dictionary=True)
        try:
            self._ensure_document_columns(cursor)
            self._ensure_signature_columns(cursor)
            connection.commit()

            if solo_codigo:
                where = 'fd.codigo_verificacion = %s'
                params = (clave,)
            else:
                where = """(
                    fd.codigo_verificacion = %s OR
                    fd.qr_payload = %s OR
                    fd.firma_digital = %s OR
                    fd.hash_documento = %s OR
                    fd.clave_publica = %s
                )"""
                params = (clave, clave, clave, clave, clave)

            cursor.execute(f"""
                SELECT fd.documento_id, fd.razon, fd.ubicacion, fd.hash_documento,
                       fd.codigo_verificacion, fd.qr_payload, fd.fecha_firma,
                       fd.algoritmo_firma, fd.firmante_nombre, fd.firmante_curp,
                       fd.firmante_cargo, dp.titulo, dp.ruta_archivo_firmado
                FROM Firmas_Documentos fd
                INNER JOIN Documentos_PDF dp ON dp.id = fd.documento_id
                WHERE {where}
                ORDER BY fd.fecha_firma DESC
                LIMIT 1
            """, params)
            firma = cursor.fetchone()
            if not firma:
                return {'success': False, 'message': 'No se encontro una firma con esa clave'}

            firma['fecha_firma'] = firma['fecha_firma'].strftime('%Y-%m-%d %H:%M:%S') if firma.get('fecha_firma') else ''
            firma['tiene_documento'] = bool(firma.get('ruta_archivo_firmado') and os.path.exists(firma['ruta_archivo_firmado']))
            return {
                'success': True,
                'message': 'Firma encontrada',
                'firma': firma
            }
        except Exception as e:
            return {'success': False, 'message': str(e)}
        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def _ensure_signature_columns(cursor):
        """Asegura columnas nuevas sin romper instalaciones existentes."""
        columns = {
            'codigo_verificacion': "ALTER TABLE Firmas_Documentos ADD COLUMN codigo_verificacion VARCHAR(64)",
            'qr_payload': "ALTER TABLE Firmas_Documentos ADD COLUMN qr_payload TEXT",
            'qr_code': "ALTER TABLE Firmas_Documentos ADD COLUMN qr_code LONGTEXT",
            'firmante_nombre': "ALTER TABLE Firmas_Documentos ADD COLUMN firmante_nombre VARCHAR(255)",
            'firmante_curp': "ALTER TABLE Firmas_Documentos ADD COLUMN firmante_curp VARCHAR(18)",
            'firmante_cargo': "ALTER TABLE Firmas_Documentos ADD COLUMN firmante_cargo VARCHAR(150)"
        }
        cursor.execute("SHOW COLUMNS FROM Firmas_Documentos")
        existing = {row['Field'] if isinstance(row, dict) else row[0] for row in cursor.fetchall()}
        for column, statement in columns.items():
            if column not in existing:
                cursor.execute(statement)

    @staticmethod
    def _ensure_document_columns(cursor):
        """Agrega columnas para guardar el archivo firmado."""
        columns = {
            'ruta_archivo_firmado': "ALTER TABLE Documentos_PDF ADD COLUMN ruta_archivo_firmado VARCHAR(500)",
            'hash_archivo_firmado': "ALTER TABLE Documentos_PDF ADD COLUMN hash_archivo_firmado VARCHAR(255)"
        }
        cursor.execute("SHOW COLUMNS FROM Documentos_PDF")
        existing = {row['Field'] if isinstance(row, dict) else row[0] for row in cursor.fetchall()}
        for column, statement in columns.items():
            if column not in existing:
                cursor.execute(statement)
