# Sistema Generador de Documentos Oficiales con Firma Digital

## Descripción del sistema

El presente proyecto consiste en el desarrollo e implementación de un sistema web para la generación, gestión, firma y certificación digital de documentos oficiales. El sistema permite a los usuarios iniciar sesión, generar o subir documentos en formato PDF, aplicar mecanismos de firma digital, emitir constancias de certificación y verificar la integridad de los archivos mediante técnicas criptográficas.

La plataforma fue desarrollada con el propósito de reducir el uso de procesos administrativos manuales, como la elaboración de documentos físicos y la firma manuscrita, incorporando herramientas digitales que fortalecen la seguridad, trazabilidad e integridad de la información.

El sistema utiliza el algoritmo SHA-256 para generar una huella digital única del documento y RSA para la generación de firmas digitales. Además, permite almacenar información relacionada con usuarios, documentos, firmas, hashes, estados y registros de auditoría dentro de una base de datos MySQL.

## Funcionalidades principales

* Registro e inicio de sesión de usuarios.
* Carga de documentos PDF.
* Generación de documentos oficiales.
* Cálculo de hash SHA-256.
* Firma digital mediante RSA.
* Generación de documentos firmados.
* Generación de códigos QR de verificación.
* Emisión de constancias de certificación digital.
* Validación de integridad de documentos.
* Consulta y descarga de documentos firmados.
* Registro de información en base de datos MySQL.

## Tecnologías utilizadas

### Backend

* Python
* Flask
* Flask-CORS
* PyJWT
* Gunicorn / WSGI

### Frontend

* HTML
* CSS
* JavaScript

### Base de datos

* MySQL

### Seguridad y criptografía

* SHA-256
* RSA
* JWT
* Firma digital
* Hash criptográfico

### Generación y manejo de archivos

* ReportLab
* PyPDF / pypdf
* QRCode
* Pillow

### Control de versiones y despliegue

* Git
* GitHub
* PythonAnywhere
* Entorno Python / Anaconda

## Estructura del proyecto

```text
Firma Digital RSA/
│
├── config/
│   └── Archivos de configuración del sistema
│
├── models/
│   └── Módulos principales del sistema
│
├── static/
│   └── Archivos CSS, JavaScript e imágenes
│
├── templates/
│   └── Plantillas HTML del sistema
│
├── app.py
│   └── Archivo principal de la aplicación Flask
│
├── requirements.txt
│   └── Dependencias necesarias del proyecto
│
├── runtime.txt
│   └── Versión de Python utilizada
│
├── Procfile
│   └── Configuración de ejecución para despliegue
│
├── .gitignore
│   └── Archivos y carpetas excluidas del repositorio
│
└── README.md
    └── Documentación general del proyecto
```

## Instalación del proyecto en entorno local

### 1. Clonar el repositorio

```bash
git clone ENLACE_DEL_REPOSITORIO
```

### 2. Entrar a la carpeta del proyecto

```bash
cd "Firma Digital RSA"
```

### 3. Crear un entorno virtual

```bash
python -m venv .venv
```

### 4. Activar el entorno virtual

En Windows:

```bash
.venv\Scripts\activate
```

En Linux o macOS:

```bash
source .venv/bin/activate
```

### 5. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 6. Configurar la base de datos

Crear una base de datos en MySQL para el sistema. Posteriormente, configurar los datos de conexión dentro del archivo correspondiente en la carpeta `config/`.

Ejemplo de datos requeridos:

```text
Host: localhost
Usuario: root
Contraseña: ********
Base de datos: firma_digital
Puerto: 3306
```

### 7. Ejecutar el sistema

```bash
python app.py
```

### 8. Abrir el sistema en el navegador

```text
http://localhost:5000
```

## Instalación y despliegue en PythonAnywhere

El sistema fue desplegado en PythonAnywhere, una plataforma de tipo PaaS compatible con aplicaciones desarrolladas en Python y Flask.

Pasos generales realizados:

1. Creación de cuenta en PythonAnywhere.
2. Carga o clonación del repositorio desde GitHub.
3. Configuración del entorno Python / Anaconda.
4. Instalación de dependencias desde `requirements.txt`.
5. Configuración del archivo WSGI.
6. Configuración de la base de datos MySQL.
7. Configuración de rutas para archivos estáticos y plantillas.
8. Recarga de la aplicación web.
9. Validación del sistema desde la URL pública.

## Manejo de ramas

Para organizar el desarrollo del proyecto se utilizará una estrategia básica de ramas en Git.

### Rama principal de producción

```text
main
```

Esta rama contiene la versión estable del sistema. En ella se almacena el código funcional que puede ser desplegado en el hosting web.

### Rama de desarrollo

```text
develop
```

Esta rama se utiliza para integrar nuevas funciones, correcciones y pruebas antes de enviarlas a producción.

### Ramas de funcionalidades

Para nuevas características o correcciones específicas, se pueden crear ramas adicionales con nombres descriptivos.

Ejemplos:

```text
feature/firma-digital
feature/certificacion-pdf
feature/verificacion-documentos
fix/error-login
fix/subida-archivos
```

## Ejemplo de flujo de trabajo con Git

Crear rama de desarrollo:

```bash
git checkout -b develop
```

Crear una rama para una nueva función:

```bash
git checkout -b feature/certificacion-pdf
```

Agregar cambios:

```bash
git add .
```

Crear commit descriptivo:

```bash
git commit -m "Agrega módulo de certificación digital en PDF"
```

Subir cambios a GitHub:

```bash
git push origin feature/certificacion-pdf
```

Unir cambios a la rama de desarrollo:

```bash
git checkout develop
git merge feature/certificacion-pdf
```

Enviar versión estable a producción:

```bash
git checkout main
git merge develop
git push origin main
```

## Ejemplos de commits descriptivos

```text
Agrega estructura inicial del proyecto Flask
Configura conexión a base de datos MySQL
Implementa inicio de sesión con JWT
Agrega módulo de carga de documentos PDF
Implementa cálculo de hash SHA-256
Agrega firma digital mediante RSA
Genera constancia de certificación digital en PDF
Agrega código QR para verificación de documentos
Corrige rutas de descarga de documentos firmados
Actualiza documentación del proyecto
```

## Archivos excluidos del repositorio

El archivo `.gitignore` evita subir archivos temporales, claves privadas, documentos generados y datos sensibles.

Entre los archivos y carpetas excluidos se encuentran:

```text
__pycache__/
.venv/
.env
uploads/
certificaciones/
keys/
*.pem
*.key
*.log
```

Estas carpetas no se suben al repositorio porque pueden contener documentos privados, certificados generados o claves utilizadas por el sistema.

## Integrantes del equipo

* Oscar Colorado González
* Anett Sabino Sánchez
* Alan Mateo Martínez
* Brandon Samano Samano
* Joanna Caren Tomas Rodriguez

## Enlace del repositorio

```text
Agregar aquí el enlace del repositorio de GitHub:
https://github.com/usuario/nombre-del-repositorio
```

## Estado del proyecto

El sistema se encuentra en fase de implementación y despliegue, con módulos funcionales para la gestión documental, firma digital, certificación y validación de documentos.

## Conclusión

El uso de GitHub como herramienta de control de versiones permite documentar el avance del proyecto, mantener un historial organizado de cambios y facilitar la colaboración entre integrantes del equipo. Además, el manejo de ramas permite separar el desarrollo de nuevas funcionalidades de la versión estable del sistema, favoreciendo una implementación más ordenada y segura.
