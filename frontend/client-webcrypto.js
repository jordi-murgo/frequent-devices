/**
 * Cliente FIDO2 para autenticación de dispositivos frecuentes
 * Se encarga de la generación de claves, firma de desafíos y comunicación con el servidor
 */

// Importar el generador de DeviceID
import { generateDeviceId } from './TrustDeviceGenerator.js';

/**
 * Clase para manejar la autenticación de dispositivos frecuentes
 */
export class FrequentDeviceWebCryptoClient {
    constructor(serverUrl = '/api') {
        this.serverUrl = serverUrl;
        this.deviceId = null;
        this.publicKey = null;
        this.privateKey = null;
    }

    /**
     * Genera un ID de dispositivo único
     * @returns {Promise<string>} El ID del dispositivo generado
     */
    async generateDeviceId() {
        try {
            this.deviceId = await generateDeviceId();
            return this.deviceId + '-wc';
        } catch (error) {
            console.error('Error al generar Device ID:', error);
            throw error;
        }
    }

    /**
     * Genera un par de claves criptográficas para el dispositivo
     * @returns {Promise<Object>} Objeto con las claves generadas
     */
    async generateKeyPair() {
        try {
            // Generar par de claves RSA-PSS para firma/verificación
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSASSA-PKCS1-v1_5",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: "SHA-256",
                },
                true,
                ["sign", "verify"]
            );

            // Exportar claves
            this.publicKey = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
            this.privateKey = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);
            
            // Guardar la clave privada en localStorage (cifrada)
            await this.storePrivateKey();

            return {
                publicKey: this.publicKey,
                privateKey: this.privateKey
            };
        } catch (error) {
            console.error('Error al generar claves:', error);
            throw error;
        }
    }

    /**
     * Almacena la clave privada de forma segura (cifrada con el deviceId)
     * @returns {Promise<boolean>} True si se almacenó correctamente
     */
    async storePrivateKey() {
        try {
            if (!this.deviceId || !this.privateKey) {
                throw new Error('Se requiere deviceId y privateKey para almacenar');
            }

            // Encriptar la clave privada usando el deviceId como contraseña
            const encryptedPrivateKey = await this.encryptPrivateKey(this.privateKey, this.deviceId);

            // Almacenar la clave privada encriptada en localStorage para persistencia
            localStorage.setItem("frequentDevicePrivateKey", JSON.stringify(encryptedPrivateKey));
            return true;
        } catch (error) {
            console.error('Error al almacenar clave privada:', error);
            throw error;
        }
    }

    /**
     * Encripta la clave privada usando el deviceId como contraseña
     * @param {Object} privateKey - Clave privada en formato JWK
     * @param {string} password - Contraseña para cifrar (deviceId)
     * @returns {Promise<Object>} Objeto con la clave privada cifrada
     */
    async encryptPrivateKey(privateKey, password) {
        try {
            // Convertir el password (deviceId) a una clave de encriptación
            const encoder = new TextEncoder();
            const passwordData = encoder.encode(password);
            const passwordHash = await window.crypto.subtle.digest('SHA-256', passwordData);

            // Importar la clave para usar en encriptación AES-GCM
            const encryptionKey = await window.crypto.subtle.importKey(
                'raw',
                passwordHash,
                { name: 'AES-GCM' },
                false,
                ['encrypt']
            );

            // Generar un vector de inicialización (IV) aleatorio
            const iv = window.crypto.getRandomValues(new Uint8Array(12));

            // Encriptar la clave privada
            const privateKeyStr = JSON.stringify(privateKey);
            const privateKeyData = encoder.encode(privateKeyStr);
            const encryptedData = await window.crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                encryptionKey,
                privateKeyData
            );

            // Convertir a formato que se pueda almacenar
            return {
                iv: Array.from(iv),
                encryptedData: Array.from(new Uint8Array(encryptedData))
            };
        } catch (error) {
            console.error('Error al encriptar la clave privada:', error);
            throw error;
        }
    }

    /**
     * Recupera y descifra la clave privada almacenada
     * @param {string} customPassword - Contraseña personalizada (opcional)
     * @returns {Promise<CryptoKey>} Clave privada importada lista para usar
     */
    async retrievePrivateKey(customPassword = null) {
        try {
            const storedEncryptedKey = localStorage.getItem("frequentDevicePrivateKey");
            if (!storedEncryptedKey) {
                throw new Error('No se encontró clave privada almacenada');
            }

            // Usar la contraseña personalizada si se proporciona, de lo contrario usar deviceId
            const password = customPassword || this.deviceId;
            if (!password) {
                throw new Error('Se requiere una contraseña o deviceId para descifrar');
            }

            // Desencriptar la clave privada
            const encryptedKey = JSON.parse(storedEncryptedKey);
            const decryptedPrivateKey = await this.decryptPrivateKey(encryptedKey, password);
            this.privateKey = decryptedPrivateKey;

            // Importar la clave para firma
            const importedKey = await window.crypto.subtle.importKey(
                "jwk",
                decryptedPrivateKey,
                {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: "SHA-256",
                },
                true,
                ["sign"]
            );

            return importedKey;
        } catch (error) {
            console.error('Error al recuperar clave privada:', error);
            throw error;
        }
    }

    /**
     * Descifra la clave privada usando el deviceId como contraseña
     * @param {Object} encryptedKey - Objeto con la clave privada cifrada
     * @param {string} password - Contraseña para descifrar (deviceId)
     * @returns {Promise<Object>} Clave privada descifrada en formato JWK
     */
    async decryptPrivateKey(encryptedKey, password) {
        try {
            // Convertir el password a una clave de desencriptación
            const encoder = new TextEncoder();
            const passwordData = encoder.encode(password);
            const passwordHash = await window.crypto.subtle.digest('SHA-256', passwordData);

            // Importar la clave para usar en desencriptación AES-GCM
            const decryptionKey = await window.crypto.subtle.importKey(
                'raw',
                passwordHash,
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );

            // Reconstruir el IV y los datos encriptados
            const iv = new Uint8Array(encryptedKey.iv);
            const encryptedData = new Uint8Array(encryptedKey.encryptedData);

            // Desencriptar la clave privada
            const decryptedData = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                decryptionKey,
                encryptedData
            );

            // Convertir de vuelta a objeto
            const decoder = new TextDecoder();
            const decryptedStr = decoder.decode(decryptedData);
            return JSON.parse(decryptedStr);
        } catch (error) {
            console.error('Error al desencriptar la clave privada:', error);
            throw error;
        }
    }

    /**
     * Registra el dispositivo en el servidor
     * @returns {Promise<Object>} Respuesta del servidor
     */
    async registerDevice() {
        try {
            if (!this.deviceId) {
                throw new Error('Se requiere generar un deviceId antes de registrar');
            }

            if (!this.publicKey) {
                // Si no hay claves, generarlas
                await this.generateKeyPair();
            }

            // Enviar la clave pública al servidor
            const response = await fetch(`${this.serverUrl}/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    deviceId: this.deviceId,
                    publicKey: this.publicKey
                })
            });

            const data = await response.json();
            if (!data.success) {
                throw new Error(data.error || 'Error al registrar el dispositivo');
            }

            return data;
        } catch (error) {
            console.error('Error al registrar dispositivo:', error);
            throw error;
        }
    }

    /**
     * Solicita un challenge al servidor
     * @returns {Promise<string>} El challenge generado
     */
    async requestChallenge() {
        try {
            if (!this.deviceId) {
                throw new Error('Se requiere deviceId para solicitar un challenge');
            }

            const response = await fetch(`${this.serverUrl}/challenge?deviceId=${this.deviceId}`);
            const data = await response.json();

            if (!data.success) {
                throw new Error(data.error || 'Error al solicitar challenge');
            }

            return data.challenge;
        } catch (error) {
            console.error('Error al solicitar challenge:', error);
            throw error;
        }
    }

    /**
     * Firma un challenge con la clave privada
     * @param {string} challenge - El challenge a firmar
     * @param {string} customPassword - Contraseña personalizada (opcional)
     * @returns {Promise<string>} La firma en formato base64
     */
    async signChallenge(challenge, customPassword = null) {
        try {
            // Recuperar la clave privada
            const privateKey = await this.retrievePrivateKey(customPassword);

            // Convertir el challenge a ArrayBuffer
            const encoder = new TextEncoder();
            const challengeData = encoder.encode(challenge);

            // Firmar el challenge
            const signature = await window.crypto.subtle.sign(
                {
                    name: "RSASSA-PKCS1-v1_5"
                },
                privateKey,
                challengeData
            );

            // Convertir la firma a base64
            return this.arrayBufferToBase64(signature);
        } catch (error) {
            console.error('Error al firmar challenge:', error);
            throw error;
        }
    }

    /**
     * Verifica la firma del challenge en el servidor
     * @param {string} challenge - El challenge firmado
     * @param {string} signature - La firma en formato base64
     * @returns {Promise<Object>} Respuesta del servidor
     */
    async verifySignature(challenge, signature) {
        try {
            if (!this.deviceId) {
                throw new Error('Se requiere deviceId para verificar la firma');
            }

            const response = await fetch(`${this.serverUrl}/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    deviceId: this.deviceId,
                    challenge,
                    signature
                })
            });

            const data = await response.json();
            if (!data.success) {
                throw new Error(data.error || 'Error al verificar la firma');
            }

            return data;
        } catch (error) {
            console.error('Error al verificar firma:', error);
            throw error;
        }
    }

    /**
     * Realiza el proceso completo de autenticación
     * @param {string} customPassword - Contraseña personalizada (opcional)
     * @returns {Promise<Object>} Resultado de la autenticación
     */
    async authenticate(customPassword = null) {
        try {
            // 1. Solicitar un challenge al servidor
            const challenge = await this.requestChallenge();
            console.log('Challenge recibido:', challenge);

            // 2. Firmar el challenge con la clave privada
            const signature = await this.signChallenge(challenge, customPassword);
            console.log('Challenge firmado');

            // 3. Enviar la firma al servidor para verificación
            const verificationResult = await this.verifySignature(challenge, signature);
            console.log('Verificación completada:', verificationResult);

            return verificationResult;
        } catch (error) {
            console.error('Error en el proceso de autenticación:', error);
            throw error;
        }
    }
    
    /**
     * Valida si el dispositivo está registrado en el servidor
     * Realiza una verificación simple solicitando un challenge
     * @returns {Promise<boolean>} True si el dispositivo es válido
     */
    async validateDevice() {
        try {
            if (!this.deviceId) {
                throw new Error('Se requiere deviceId para validar el dispositivo');
            }
            
            // Intentar solicitar un challenge al servidor
            // Si el dispositivo no está registrado, esto fallará
            await this.requestChallenge();
            
            // Si llegamos aquí, el dispositivo es válido
            return true;
        } catch (error) {
            console.error('Error al validar dispositivo:', error);
            throw error;
        }
    }

    /**
     * Convierte un ArrayBuffer a una cadena Base64
     * @param {ArrayBuffer} buffer - El buffer a convertir
     * @returns {string} Cadena en formato Base64
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Convierte una cadena Base64 a ArrayBuffer
     * @param {string} base64 - Cadena en formato Base64
     * @returns {ArrayBuffer} El buffer resultante
     */
    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
}
