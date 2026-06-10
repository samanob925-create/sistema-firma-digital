import os
import json
import hashlib
import base64
import platform
import textwrap
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors


class CertificacionArchivos:
    def __init__(self):
        self.keys_folder = "keys"
        self.cert_folder = "certificaciones"

        self.private_key_path = os.path.join(self.keys_folder, "certificador_privada.pem")
        self.public_key_path = os.path.join(self.keys_folder, "certificador_publica.pem")

        os.makedirs(self.keys_folder, exist_ok=True)
        os.makedirs(self.cert_folder, exist_ok=True)

        self._crear_claves_si_no_existen()

    def _crear_claves_si_no_existen(self):
        """Crea las claves RSA del sistema certificador si todavía no existen."""
        if os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path):
            return

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        with open(self.private_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        with open(self.public_key_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    def _cargar_clave_privada(self):
        """Carga la clave privada del sistema certificador."""
        with open(self.private_key_path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None
            )

    def _cargar_clave_publica(self):
        """Carga la clave pública del sistema certificador."""
        with open(self.public_key_path, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    def calcular_hash_sha256(self, ruta_archivo):
        """Calcula el hash SHA-256 del archivo."""
        sha256 = hashlib.sha256()

        with open(ruta_archivo, "rb") as archivo:
            for bloque in iter(lambda: archivo.read(4096), b""):
                sha256.update(bloque)

        return sha256.hexdigest()

    def certificar_archivo(self, ruta_archivo, usuario_id, documento_id=None, origen="archivo_subido"):
        """Certifica un archivo generando hash, firma, JSON técnico y PDF oficial."""
        if not os.path.exists(ruta_archivo):
            return {
                "success": False,
                "message": "El archivo no existe"
            }

        hash_archivo = self.calcular_hash_sha256(ruta_archivo)
        private_key = self._cargar_clave_privada()

        firma = private_key.sign(
            hash_archivo.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        firma_base64 = base64.b64encode(firma).decode("utf-8")
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        constancia = {
            "tipo": "Certificación digital de archivo",
            "documento_id": documento_id,
            "usuario_id": usuario_id,
            "origen": origen,
            "ruta_archivo": ruta_archivo,
            "nombre_archivo": os.path.basename(ruta_archivo),
            "hash_sha256": hash_archivo,
            "algoritmo_hash": "SHA-256",
            "algoritmo_firma": "RSA-2048",
            "firma_certificacion": firma_base64,
            "sistema_certificador": "Sistema de Firma Digital IA",
            "entorno": platform.system(),
            "fecha_certificacion": fecha
        }

        nombre_base = f"certificacion_{documento_id or usuario_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        ruta_constancia = os.path.join(self.cert_folder, f"{nombre_base}.json")

        with open(ruta_constancia, "w", encoding="utf-8") as f:
            json.dump(constancia, f, indent=4, ensure_ascii=False)

        ruta_pdf = self.generar_certificado_pdf(constancia, nombre_base)

        return {
            "success": True,
            "message": "Archivo certificado correctamente",
            "hash_sha256": hash_archivo,
            "firma_certificacion": firma_base64,
            "ruta_constancia": ruta_constancia,
            "ruta_certificado_pdf": ruta_pdf,
            "fecha_certificacion": fecha
        }

    def generar_certificado_pdf(self, constancia, nombre_base=None):
        """Genera una constancia oficial en PDF de la certificación digital."""
        pdf_folder = os.path.join(self.cert_folder, "pdf")
        os.makedirs(pdf_folder, exist_ok=True)

        if not nombre_base:
            documento_id = constancia.get("documento_id") or constancia.get("usuario_id")
            fecha_archivo = datetime.now().strftime("%Y%m%d_%H%M%S")
            nombre_base = f"certificado_digital_{documento_id}_{fecha_archivo}"

        ruta_pdf = os.path.join(pdf_folder, f"{nombre_base}.pdf")

        pdf = canvas.Canvas(ruta_pdf, pagesize=letter)
        width, height = letter

        pdf.setFillColor(colors.HexColor("#f8fafc"))
        pdf.rect(0, 0, width, height, fill=1, stroke=0)

        pdf.setStrokeColor(colors.HexColor("#1e3a8a"))
        pdf.setLineWidth(2)
        pdf.roundRect(35, 35, width - 70, height - 70, 12, stroke=1, fill=0)

        pdf.setFillColor(colors.HexColor("#0f172a"))
        pdf.roundRect(35, height - 120, width - 70, 85, 12, fill=1, stroke=0)

        pdf.setFillColor(colors.white)
        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawCentredString(width / 2, height - 67, "CONSTANCIA DE CERTIFICACIÓN DIGITAL")

        pdf.setFont("Helvetica", 10)
        pdf.drawCentredString(width / 2, height - 88, "Sistema de Firma Digital IA")

        y = height - 150

        pdf.setFillColor(colors.HexColor("#111827"))
        pdf.setFont("Helvetica", 10)
        intro = (
            "Por medio de la presente, el sistema certifica que el archivo indicado fue "
            "registrado y protegido mediante mecanismos criptográficos de integridad, "
            "autenticidad y trazabilidad."
        )
        for linea in textwrap.wrap(intro, width=95):
            pdf.drawString(55, y, linea)
            y -= 13

        y -= 15

        pdf.setFillColor(colors.HexColor("#1e3a8a"))
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(55, y, "Datos del documento certificado")
        y -= 22

        datos = [
            ("Tipo de constancia", constancia.get("tipo", "")),
            ("Documento ID", str(constancia.get("documento_id", ""))),
            ("Usuario ID", str(constancia.get("usuario_id", ""))),
            ("Nombre del archivo", constancia.get("nombre_archivo", "")),
            ("Origen", constancia.get("origen", "")),
            ("Fecha de certificación", constancia.get("fecha_certificacion", "")),
            ("Sistema certificador", constancia.get("sistema_certificador", "")),
            ("Entorno", constancia.get("entorno", "")),
        ]

        for etiqueta, valor in datos:
            pdf.setFillColor(colors.HexColor("#374151"))
            pdf.setFont("Helvetica-Bold", 9)
            pdf.drawString(55, y, f"{etiqueta}:")

            pdf.setFillColor(colors.HexColor("#111827"))
            pdf.setFont("Helvetica", 9)
            valor_texto = str(valor or "")
            if len(valor_texto) > 70:
                valor_texto = valor_texto[:67] + "..."
            pdf.drawString(200, y, valor_texto)

            y -= 16

        y -= 10

        pdf.setFillColor(colors.HexColor("#1e3a8a"))
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(55, y, "Información criptográfica")
        y -= 22

        crypto_datos = [
            ("Algoritmo de hash", constancia.get("algoritmo_hash", "")),
            ("Algoritmo de firma", constancia.get("algoritmo_firma", "")),
        ]

        for etiqueta, valor in crypto_datos:
            pdf.setFillColor(colors.HexColor("#374151"))
            pdf.setFont("Helvetica-Bold", 9)
            pdf.drawString(55, y, f"{etiqueta}:")

            pdf.setFillColor(colors.HexColor("#111827"))
            pdf.setFont("Helvetica", 9)
            pdf.drawString(200, y, str(valor or ""))

            y -= 16

        y -= 6

        pdf.setFont("Helvetica-Bold", 9)
        pdf.setFillColor(colors.HexColor("#374151"))
        pdf.drawString(55, y, "Hash SHA-256:")
        y -= 14

        pdf.setFont("Courier", 7.5)
        pdf.setFillColor(colors.HexColor("#111827"))
        hash_texto = constancia.get("hash_sha256", "")
        for linea in textwrap.wrap(hash_texto, width=90):
            pdf.drawString(55, y, linea)
            y -= 11

        y -= 10

        pdf.setFont("Helvetica-Bold", 9)
        pdf.setFillColor(colors.HexColor("#374151"))
        pdf.drawString(55, y, "Firma digital de certificación:")
        y -= 14

        pdf.setFont("Courier", 6)
        pdf.setFillColor(colors.HexColor("#111827"))
        firma_texto = constancia.get("firma_certificacion", "")

        for linea in textwrap.wrap(firma_texto, width=120)[:10]:
            if y < 150:
                break
            pdf.drawString(55, y, linea)
            y -= 9

        pdf.setFillColor(colors.HexColor("#e0f2fe"))
        pdf.roundRect(50, 78, width - 100, 90, 8, fill=1, stroke=0)

        pdf.setFillColor(colors.HexColor("#0f172a"))
        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawString(65, 145, "Declaración de validez")

        pdf.setFont("Helvetica", 8.5)
        texto = (
            "Esta constancia permite verificar que el archivo no ha sido modificado "
            "después de su certificación. Cualquier alteración en el contenido del archivo "
            "generará un hash diferente e invalidará la certificación digital."
        )

        y_text = 130
        for linea in textwrap.wrap(texto, width=94):
            pdf.drawString(65, y_text, linea)
            y_text -= 11

        pdf.setFillColor(colors.HexColor("#64748b"))
        pdf.setFont("Helvetica", 8)
        pdf.drawCentredString(width / 2, 54, "Documento generado automáticamente por el Sistema de Firma Digital IA")
        pdf.drawCentredString(width / 2, 43, "Certificación basada en hash SHA-256 y firma digital RSA-2048")

        pdf.save()
        return ruta_pdf

    def verificar_certificacion(self, ruta_archivo, firma_base64):
        """Verifica que la firma corresponda al hash actual del archivo."""
        try:
            if not os.path.exists(ruta_archivo):
                return {
                    "success": False,
                    "message": "El archivo no existe"
                }

            hash_actual = self.calcular_hash_sha256(ruta_archivo)
            public_key = self._cargar_clave_publica()
            firma = base64.b64decode(firma_base64)

            public_key.verify(
                firma,
                hash_actual.encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            return {
                "success": True,
                "message": "La certificación es válida. El archivo no fue alterado.",
                "hash_actual": hash_actual
            }

        except Exception:
            return {
                "success": False,
                "message": "La certificación no es válida. El archivo pudo ser alterado."
            }
