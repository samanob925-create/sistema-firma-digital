import hashlib
import json
import os
import cv2
import numpy as np
from datetime import datetime
from models.database import Database
from config.config import Config

class BiometricAuth:
    def __init__(self):
        self.db = Database()
        self.template_folder = Config.BIOMETRIC_FOLDER
        os.makedirs(self.template_folder, exist_ok=True)
        # Umbral de similitud para verificación
        self.similarity_threshold = 0.65
    
    def enroll_fingerprint(self, user_id, fingerprint_image, quality_score=None):
        """Registrar huella digital usando OpenCV - Mejorado para sensores reales"""
        try:
            # Convertir imagen a array numpy
            if isinstance(fingerprint_image, str):
                # Es una ruta de archivo
                img = cv2.imread(fingerprint_image, cv2.IMREAD_GRAYSCALE)
            else:
                # Es datos de imagen
                nparr = np.frombuffer(fingerprint_image, np.uint8)
                img = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)
            
            if img is None:
                return {'success': False, 'message': 'Imagen de huella inválida'}
            
            # Validar calidad mínima de la imagen
            if not self._validate_image_quality(img):
                return {'success': False, 'message': 'Calidad de imagen insuficiente. Por favor, intenta de nuevo.'}
            
            # Mejorar contraste y preprocesar
            img = self._preprocess_fingerprint(img)
            
            # Extraer características robustas
            features = self.extract_features(img)
            if not features:
                return {'success': False, 'message': 'No se pudieron extraer características de la huella'}
            
            # Guardar template
            os.makedirs(self.template_folder, exist_ok=True)
            template_file = os.path.join(self.template_folder, f"{user_id}.json")
            
            template_data = {
                'user_id': user_id,
                'features': features,
                'hash': hashlib.sha256(str(features).encode()).hexdigest(),
                'enrolled_at': datetime.now().isoformat(),
                'quality_score': quality_score or 100
            }
            
            with open(template_file, 'w') as f:
                json.dump(template_data, f, indent=2)
            
            # Actualizar base de datos
            connection = self.db.get_connection()
            if connection:
                cursor = connection.cursor()
                cursor.execute("""
                    UPDATE Usuarios 
                    SET biometric_enabled = 1, fingerprint_hash = %s, biometric_enrolled_date = NOW()
                    WHERE id_Usuario = %s
                """, (template_data['hash'], user_id))
                connection.commit()
                cursor.close()
                connection.close()
            
            return {'success': True, 'message': 'Huella registrada exitosamente'}
            
        except Exception as e:
            print(f"❌ Error registrando huella: {str(e)}")
            return {'success': False, 'message': f'Error registrando huella: {str(e)}'}
    
    def _preprocess_fingerprint(self, img):
        """Preprocesar imagen de huella para mejores resultados"""
        try:
            # Ecualizar histograma
            img = cv2.equalizeHist(img)
            
            # Aplicar CLAHE (Contrast Limited Adaptive Histogram Equalization)
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            img = clahe.apply(img)
            
            # Aplicar Gaussianblur para reducir ruido
            img = cv2.GaussianBlur(img, (5, 5), 0)
            
            # Binarización adaptativa
            img = cv2.adaptiveThreshold(img, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                        cv2.THRESH_BINARY, 11, 2)
            
            return img
        except:
            return img
    
    def _validate_image_quality(self, img):
        """Validar que la imagen tenga suficiente calidad"""
        try:
            # Verificar que la imagen no esté vacía
            if img.size == 0:
                return False
            
            # Calcular estadísticas de brillo
            brightness = np.mean(img)
            if brightness < 30 or brightness > 225:
                return False  # Muy oscura o muy clara
            
            # Calcular varianza (contraste)
            variance = np.var(img)
            if variance < 100:
                return False  # Contraste insuficiente
            
            return True
        except:
            return True  # Permitir si hay error en validación
    
    def extract_features(self, img):
        """Extraer características robustas de la huella digital"""
        try:
            # Usar SIFT para características más robustas (si está disponible)
            # Si no está disponible, usar ORB
            try:
                sift = cv2.SIFT_create()
                keypoints, descriptors = sift.detectAndCompute(img, None)
                
                if descriptors is not None:
                    # Retornar descriptores SIFT
                    return {
                        'method': 'SIFT',
                        'keypoints_count': len(keypoints) if keypoints else 0,
                        'descriptors': descriptors.tolist()
                    }
            except (AttributeError, cv2.error):
                # SIFT no disponible, usar ORB
                pass
            
            # Fallback a ORB
            orb = cv2.ORB_create(nfeatures=5000)
            keypoints, descriptors = orb.detectAndCompute(img, None)
            
            if descriptors is not None and len(keypoints) > 0:
                return {
                    'method': 'ORB',
                    'keypoints_count': len(keypoints),
                    'descriptors': descriptors.tolist()
                }
            else:
                # Si falla extracción de características, usar hash de imagen
                return {
                    'method': 'HASH',
                    'hash': hashlib.sha256(img.tobytes()).hexdigest(),
                    'keypoints_count': 0
                }
        except Exception as e:
            print(f"❌ Error extrayendo características: {str(e)}")
            return None
    
    def verify_fingerprint(self, user_id, fingerprint_image):
        """Verificar huella digital contra usuario específico"""
        try:
            # Procesar imagen de entrada
            if isinstance(fingerprint_image, str):
                input_img = cv2.imread(fingerprint_image, cv2.IMREAD_GRAYSCALE)
            else:
                nparr = np.frombuffer(fingerprint_image, np.uint8)
                input_img = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)
            
            if input_img is None:
                return {'success': False, 'message': 'Imagen de huella inválida'}
            
            # Validar calidad de imagen
            if not self._validate_image_quality(input_img):
                return {'success': False, 'message': 'Calidad de imagen insuficiente. Por favor intenta de nuevo.'}
            
            # Preprocesar
            input_img = self._preprocess_fingerprint(input_img)
            input_features = self.extract_features(input_img)
            
            if not input_features:
                return {'success': False, 'message': 'No se pudieron extraer características de la huella capturada'}
            
            # Cargar template del usuario
            template_file = os.path.join(self.template_folder, f"{user_id}.json")
            
            if not os.path.exists(template_file):
                return {'success': False, 'message': 'El usuario no tiene huella registrada'}
            
            with open(template_file, 'r') as f:
                template = json.load(f)
            
            # Calcular similitud
            similarity = self.calculate_similarity(input_features, template['features'])
            
            if similarity >= self.similarity_threshold:
                return {
                    'success': True,
                    'message': 'Autenticación biométrica exitosa',
                    'score': similarity,
                    'user_id': user_id
                }
            else:
                return {
                    'success': False,
                    'message': f'Huella no coincide. Similitud: {similarity:.2%}',
                    'score': similarity
                }
            
        except Exception as e:
            print(f" Error verificando huella: {str(e)}")
            return {'success': False, 'message': f'Error verificando huella: {str(e)}'}
    
    def identify_fingerprint(self, fingerprint_image):
        """Identificar usuario por huella digital (buscar en todos los templates)"""
        try:
            # Procesar imagen de entrada
            if isinstance(fingerprint_image, str):
                input_img = cv2.imread(fingerprint_image, cv2.IMREAD_GRAYSCALE)
            else:
                nparr = np.frombuffer(fingerprint_image, np.uint8)
                input_img = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)
            
            if input_img is None:
                return {'success': False, 'message': 'Imagen de huella inválida'}
            
            # Preprocesar
            input_img = self._preprocess_fingerprint(input_img)
            input_features = self.extract_features(input_img)
            
            if not input_features:
                return {'success': False, 'message': 'No se pudieron extraer características'}
            
            # Buscar coincidencias en todos los templates
            best_match = None
            best_score = 0
            best_user_id = None
            
            if os.path.exists(self.template_folder):
                for filename in os.listdir(self.template_folder):
                    if filename.endswith('.json'):
                        try:
                            template_path = os.path.join(self.template_folder, filename)
                            with open(template_path, 'r') as f:
                                template = json.load(f)
                            
                            # Calcular similitud
                            similarity = self.calculate_similarity(input_features, template['features'])
                            
                            if similarity > best_score:
                                best_score = similarity
                                best_match = template
                                best_user_id = template['user_id']
                        except:
                            continue
            
            # Umbral de coincidencia
            if best_score >= self.similarity_threshold and best_match:
                return {
                    'success': True,
                    'message': 'Usuario identificado exitosamente',
                    'user_id': best_user_id,
                    'score': best_score
                }
            
            return {
                'success': False,
                'message': f'Huella no reconocida (similitud máxima: {best_score:.2%})',
                'score': best_score
            }
            
        except Exception as e:
            print(f"Error identificando huella: {str(e)}")
            return {'success': False, 'message': f'Error identificando huella: {str(e)}'}
    
    def calculate_similarity(self, features1, features2):
        """Calcular similitud entre características usando Hamming distance"""
        try:
            # Manejar diferentes formatos de características
            if isinstance(features1, dict) and isinstance(features2, dict):
                # Ambas son diccionarios con método, descriptores, etc.
                method1 = features1.get('method', 'HASH')
                method2 = features2.get('method', 'HASH')
                
                # Si ambos tienen hashes, comparar hashes
                if method1 == 'HASH' and method2 == 'HASH':
                    h1 = features1.get('hash', '')
                    h2 = features2.get('hash', '')
                    return 1.0 if h1 == h2 and h1 else 0.0
                
                # Si ambos tienen descriptores, comparar descriptores
                desc1 = features1.get('descriptors')
                desc2 = features2.get('descriptors')
                
                if desc1 and desc2:
                    f1 = np.array(desc1, dtype=np.uint8)
                    f2 = np.array(desc2, dtype=np.uint8)
                    
                    # Usar BFMatcher con Hamming distance
                    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
                    matches = bf.match(f1, f2)
                    
                    # Calcular score basado en matches
                    max_matches = min(len(f1), len(f2))
                    if max_matches > 0:
                        return len(matches) / max_matches
                    else:
                        return 0.0
            
            elif isinstance(features1, list) and isinstance(features2, list):
                # Formato antiguo (lista de descriptores)
                try:
                    f1 = np.array(features1, dtype=np.uint8)
                    f2 = np.array(features2, dtype=np.uint8)
                    
                    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
                    matches = bf.match(f1, f2)
                    
                    max_matches = min(len(f1), len(f2))
                    if max_matches > 0:
                        return len(matches) / max_matches
                    else:
                        return 0.0
                except:
                    return 0.0
            
            return 0.0
                
        except Exception as e:
            print(f" Error calculando similitud: {str(e)}")
            return 0.0