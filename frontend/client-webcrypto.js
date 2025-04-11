/**
 * Cliente FIDO2-like (basado en WebCrypto) para autenticación de dispositivos frecuentes
 * Se encarga de la generación de claves, firma de desafíos y comunicación con el servidor
 */

// Importar el generador de DeviceID (asumiendo que existe y funciona)
import { generateDeviceId } from './TrustDeviceGenerator.js';
// Importar la clase base
import { FrequentDeviceClient } from './frequent-device-client-interface.js';

/**
 * Clase para manejar la autenticación de dispositivos frecuentes usando WebCrypto
 */
export class FrequentDeviceWebCryptoClient extends FrequentDeviceClient {
    constructor(serverBaseUrl = '') { // Ajustar si la API está en /api o similar
        super(serverBaseUrl); // Llama al constructor de la clase base
        // Cargar valores específicos de WebCrypto desde localStorage
        this.deviceId = localStorage.getItem("frequentDeviceDeviceId") || this.deviceId; // Prioriza el storage si existe
        this.publicKey = null; // Almacenado en formato JWK
        // La clave privada no se guarda directamente en la instancia, se recupera de localStorage
    }

    /**
     * Genera un ID de dispositivo único y lo asigna a la instancia
     * @returns {Promise<string>} El ID del dispositivo generado
     */
    async ensureDeviceId() {
        if (!this.deviceId) {
            try {
                // Intenta obtenerlo de localStorage primero (si se registró previamente)
                this.deviceId = localStorage.getItem("frequentDeviceId");
                if (!this.deviceId) {
                    console.log("Generando nuevo Device ID...");
                    this.deviceId = await generateDeviceId();
                    // Opcional: guardar el deviceId en localStorage si se quiere persistir entre sesiones
                    // aunque se necesita para recuperar la clave privada de todas formas.
                    localStorage.setItem("frequentDeviceId", this.deviceId);
                }
            } catch (error) {
                console.error('Error al generar/obtener Device ID:', error);
                throw error;
            }
        }
        return this.deviceId;
    }

    /**
     * Genera un par de claves criptográficas (RSA-PSS) para el dispositivo
     * @returns {Promise<{publicKey: Object, privateKey: Object}>} Objeto con las claves JWK generadas
     */
    async generateKeyPair() {
        try {
            console.log("Generando par de claves RSA-PSS...");
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSASSA-PKCS1-v1_5", // O usar "ECDSA" con namedCurve: "P-256" para parecerse más a FIDO2
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: "SHA-256",
                },
                true, // Extractable
                ["sign", "verify"]
            );

            this.publicKey = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
            const privateKey = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

            console.log("Claves generadas. Clave pública:", this.publicKey);

            // Guardar la clave privada cifrada en localStorage
            await this.storeEncryptedPrivateKey(privateKey);

            return {
                publicKey: this.publicKey,
                privateKey: privateKey // Devolverla por si se necesita inmediatamente, pero no almacenarla en la instancia
            };
        } catch (error) {
            console.error('Error al generar claves:', error);
            throw error;
        }
    }

    /**
     * Almacena la clave privada cifrada en localStorage usando el deviceId
     * @param {Object} privateKey - Clave privada en formato JWK
     * @returns {Promise<void>}
     */
    async storeEncryptedPrivateKey(privateKey) {
        await this.ensureDeviceId(); // Asegurarse de que tenemos un deviceId
        if (!this.deviceId || !privateKey) {
            throw new Error('Se requiere deviceId y privateKey para almacenar');
        }
        try {
            console.log("Cifrando y almacenando clave privada...");
            const encryptedPrivateKey = await this.encryptPrivateKey(privateKey, this.deviceId);

            // DEBUG: Log the object before stringifying
            console.log("DEBUG: Encrypted object before stringify:", encryptedPrivateKey);

            localStorage.setItem("frequentDevicePrivateKey_enc", JSON.stringify(encryptedPrivateKey));
            // Opcional: Almacenar la clave pública también para no tener que regenerarla
            localStorage.setItem("frequentDevicePublicKey", JSON.stringify(this.publicKey));
            console.log("Clave privada cifrada almacenada en localStorage.");
        } catch (error) {
            console.error('Error al almacenar clave privada cifrada:', error);
            throw error;
        }
    }

    /**
     * Cifra la clave privada usando una clave derivada del password (deviceId)
     * @param {Object} privateKey - Clave privada en formato JWK
     * @param {string} password - Contraseña para derivar la clave de cifrado (deviceId)
     * @returns {Promise<Object>} Objeto con iv y encryptedData (como arrays)
     */
    async encryptPrivateKey(privateKey, password) {
        try {
            const encoder = new TextEncoder();
            const privateKeyStr = JSON.stringify(privateKey);
            const privateKeyData = encoder.encode(privateKeyStr);

            // Derivar clave de cifrado desde el password (deviceId) usando PBKDF2
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const passwordKey = await window.crypto.subtle.importKey(
                'raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
            );
            const encryptionKey = await window.crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
                passwordKey,
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt']
            );

            // Cifrar con AES-GCM
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encryptedData = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                encryptionKey,
                privateKeyData
            );

            return {
                salt: Array.from(salt), // Guardar salt para descifrado
                iv: Array.from(iv),
                encryptedData: Array.from(new Uint8Array(encryptedData))
            };
        } catch (error) {
            console.error('Error al encriptar la clave privada:', error);
            throw error;
        }
    }

    /**
     * Recupera y descifra la clave privada almacenada usando el deviceId.
     * @returns {Promise<CryptoKey>} Clave privada importada lista para usar (para firmar)
     */
    async retrieveAndDecryptPrivateKey() {
        await this.ensureDeviceId(); // Asegurarse de que tenemos el deviceId
        const storedEncryptedKey = localStorage.getItem("frequentDevicePrivateKey_enc");
        if (!storedEncryptedKey) {
            throw new Error('No se encontró clave privada cifrada almacenada');
        }
        if (!this.deviceId) {
             throw new Error('Se requiere deviceId para descifrar la clave');
        }

        try {
            console.log("Recuperando y descifrando clave privada...");
            // DEBUG: Log raw string from localStorage
            console.log("DEBUG: Raw string retrieved from localStorage:", storedEncryptedKey);

            const encryptedKey = JSON.parse(storedEncryptedKey);

            // DEBUG: Log parsed object
            console.log("DEBUG: Parsed object from localStorage:", encryptedKey);

            const decryptedPrivateKeyJWK = await this.decryptPrivateKey(encryptedKey, this.deviceId);

            // Importar la clave JWK descifrada para poder usarla en operaciones de firma
            const importedKey = await window.crypto.subtle.importKey(
                "jwk",
                decryptedPrivateKeyJWK,
                { // Asegurarse de que los parámetros coincidan con los de generación
                    name: "RSASSA-PKCS1-v1_5",
                    hash: "SHA-256",
                },
                true, // Extractable debe ser true si se exportó así
                ["sign"] // El propósito debe ser 'sign'
            );
            console.log("Clave privada descifrada e importada lista para usar.");
            return importedKey;
        } catch (error) {
            console.error('Error al recuperar/descifrar clave privada:', error);
            // Podría ser un deviceId incorrecto o corrupción de datos
            localStorage.removeItem("frequentDevicePrivateKey_enc"); // Eliminar clave inválida?
            localStorage.removeItem("frequentDeviceId"); // Eliminar ID asociado?
            this.deviceId = null; // Resetear deviceId
            throw error;
        }
    }

    /**
     * Descifra la clave privada usando una clave derivada del password (deviceId)
     * @param {Object} encryptedKey - Objeto con salt, iv, encryptedData
     * @param {string} password - Contraseña para derivar la clave (deviceId)
     * @returns {Promise<Object>} Clave privada descifrada en formato JWK
     */
    async decryptPrivateKey(encryptedKey, password) {
        try {
            const salt = new Uint8Array(encryptedKey.salt);
            const iv = new Uint8Array(encryptedKey.iv);
            const encryptedData = new Uint8Array(encryptedKey.encryptedData);
            const encoder = new TextEncoder();

            // DEBUG: Log reconstructed array lengths
            console.log(`DEBUG: Decrypting with Salt[${salt.length}], IV[${iv.length}], Data[${encryptedData.length}]`);

            // Derivar clave de descifrado desde el password (deviceId) usando PBKDF2 y el salt guardado
            const passwordKey = await window.crypto.subtle.importKey(
                'raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
            );
            const decryptionKey = await window.crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
                passwordKey,
                { name: 'AES-GCM', length: 256 },
                true,
                ['decrypt']
            );

            // Descifrar con AES-GCM
            const decryptedData = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                decryptionKey,
                encryptedData
            );

            // Convertir de vuelta a objeto JWK
            const decoder = new TextDecoder();
            const decryptedStr = decoder.decode(decryptedData);
            return JSON.parse(decryptedStr);
        } catch (error) {
            console.error('Error al desencriptar la clave privada (¿DeviceId incorrecto?):', error);
            throw new Error('No se pudo descifrar la clave privada. El Device ID podría ser incorrecto.');
        }
    }

     /**
     * Verifica si ya existe una clave cifrada para el deviceId actual en localStorage.
     * También carga la clave pública si existe.
     * @returns {Promise<boolean>} True si existe una clave cifrada.
     */
    async checkForExistingCredential() {
        await this.ensureDeviceId(); // Asegura que this.deviceId esté cargado
        if (!this.deviceId) {
            console.log("checkForExistingCredential: No deviceId found.");
            return false;
        }

        const storedEncryptedKey = localStorage.getItem("frequentDevicePrivateKey_enc");
        const storedPublicKey = localStorage.getItem("frequentDevicePublicKey");

        if (storedEncryptedKey && storedPublicKey) {
            console.log("checkForExistingCredential: Found stored encrypted private key and public key.");
            try {
                this.publicKey = JSON.parse(storedPublicKey);
                console.log("checkForExistingCredential: Public key loaded into client instance.");
                return true; // Indicate that essential credentials exist
            } catch (e) {
                console.error("checkForExistingCredential: Error parsing stored public key:", e);
                // Consider corrupted state, clear keys
                this.clearLocalCredentials(); 
                return false;
            }
        } else {
            console.log("checkForExistingCredential: Missing stored keys (EncryptedPrivateKey exists?", !!storedEncryptedKey, ", PublicKey exists?", !!storedPublicKey, ")");
            // Ensure client state is clean if keys are missing
            this.publicKey = null; 
            return false;
        }
    }

    /**
     * Realiza el proceso de "enrollment" (registro) en 1 paso.
     * Genera claves si no existen y envía la clave pública al servidor.
     * @returns {Promise<Object>} Respuesta del servidor
     */
    async registerDevice() {
        try {
            await this.ensureDeviceId(); // Asegura tener deviceId

            // Generar claves solo si no tenemos una clave pública (o si queremos forzar regeneración)
             if (!this.publicKey) {
                 const existing = await this.checkForExistingCredential();
                 if (!existing) {
                    console.log("Generando nuevas claves para enrollment...");
                    await this.generateKeyPair(); // Genera y almacena la privada cifrada, guarda la pública en this.publicKey
                 } else if (!this.publicKey) {
                    // Teníamos clave privada pero no pública en la instancia, cargarla
                     const storedPublicKey = localStorage.getItem("frequentDevicePublicKey");
                     if(storedPublicKey) this.publicKey = JSON.parse(storedPublicKey);
                     else {
                         // Caso raro: privada cifrada existe pero pública no. Forzar regeneración.
                         console.warn("Clave pública no encontrada en localStorage, regenerando par de claves.");
                         await this.generateKeyPair();
                     }
                 }
             }


            if (!this.publicKey) {
                 throw new Error("No se pudo obtener la clave pública para el registro.");
            }

            console.log(`Iniciando enrollment para Device ID: ${this.deviceId}`);
            console.log("Enviando clave pública al servidor:", this.publicKey);

            const response = await fetch(`${this.serverUrl}/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    deviceId: this.deviceId,
                    publicKey: this.publicKey, // Enviar clave pública en formato JWK
                    authenticationType: 'webcrypto'
                })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || `Error en el servidor durante el enrollment: ${response.statusText}`);
            }

            console.log("Enrollment completado con éxito:", data);
            return data;
        } catch (error) {
            console.error('Error en el proceso de enrollment:', error);
            throw error;
        }
    }


    /**
     * Solicita un challenge al servidor para la autenticación.
     * @returns {Promise<string>} El challenge generado por el servidor.
     */
    async requestChallenge() {
        await this.ensureDeviceId(); // Asegura tener deviceId
        if (!this.deviceId) {
            throw new Error('Se requiere deviceId para solicitar un challenge');
        }
        try {
            console.log(`Solicitando challenge para Device ID: ${this.deviceId}`);
            const response = await fetch(`${this.serverUrl}/challenge?deviceId=${encodeURIComponent(this.deviceId)}`);
            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || `Error al solicitar challenge: ${response.statusText}`);
            }
            if (!data.challenge) {
                 throw new Error('El servidor no devolvió un challenge válido.');
            }

            console.log("Challenge recibido:", data.challenge);
            return data.challenge;
        } catch (error) {
            console.error('Error al solicitar challenge:', error);
            throw error;
        }
    }

    /**
     * Firma un challenge con la clave privada recuperada y descifrada.
     * @param {string} challenge - El challenge a firmar.
     * @returns {Promise<string>} La firma en formato base64.
     */
    async signChallenge(challenge) {
        try {
            // Recuperar y descifrar la clave privada
            const privateKey = await this.retrieveAndDecryptPrivateKey();

            // Convertir el challenge (string) a ArrayBuffer
            const encoder = new TextEncoder();
            const challengeData = encoder.encode(challenge);

            console.log("Firmando el challenge...");
            // Firmar el challenge usando la clave privada importada
            const signatureBuffer = await window.crypto.subtle.sign(
                { name: "RSASSA-PKCS1-v1_5" }, // Debe coincidir con la generación/importación
                privateKey,
                challengeData
            );

            // Convertir la firma (ArrayBuffer) a base64 para enviarla
            const signatureBase64 = this.arrayBufferToBase64(signatureBuffer);
            console.log("Challenge firmado. Firma (Base64):", signatureBase64.substring(0, 20) + "..."); // Log corto
            return signatureBase64;
        } catch (error) {
            console.error('Error al firmar challenge:', error);
            throw error; // Re-lanzar para que authenticate() lo maneje
        }
    }

    /**
     * Envía el challenge firmado al servidor para su validación.
     * @param {string} challenge - El challenge original.
     * @param {string} signature - La firma en formato base64.
     * @returns {Promise<Object>} Respuesta del servidor sobre la validación.
     */
    async verifySignature(challenge, signature) {
         await this.ensureDeviceId(); // Asegura tener deviceId
         if (!this.deviceId) {
            throw new Error('Se requiere deviceId para validar la firma');
         }
        try {
            console.log(`Validando firma para Device ID: ${this.deviceId}`);
            const response = await fetch(`${this.serverUrl}/verify`, { // Cambio a /verify
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    deviceId: this.deviceId,
                    challenge: challenge,
                    signature: signature // Firma en base64
                })
            });

            const data = await response.json();

             if (!response.ok) { // Chequear status code HTTP ademas del success
                 throw new Error(data.error || `Error del servidor durante la validación: ${response.statusText}`);
             }
             // No necesariamente lanzar error si success es false, depende de cómo lo maneje el servidor
             // if (!data.success) {
             //    console.warn("Validación fallida:", data.error || "Razón desconocida");
             // }


            console.log("Respuesta de validación recibida:", data);
            return data; // Devolver la respuesta completa (puede incluir {success: boolean, error?: string})
        } catch (error) {
            console.error('Error al validar firma en el servidor:', error);
            throw error;
        }
    }

    /**
     * Realiza el proceso completo de autenticación FIDO2-like.
     * @returns {Promise<Object>} Resultado de la autenticación del servidor.
     */
    async authenticate() {
        try {
            // 0. Asegurarse de que tenemos un deviceId
            await this.ensureDeviceId();
             if (!this.deviceId) {
                 throw new Error("No se pudo obtener un Device ID para la autenticación.");
             }
            console.log(`Iniciando autenticación para Device ID: ${this.deviceId}`);

            // 1. Solicitar un challenge al servidor
            const challenge = await this.requestChallenge();

            // 2. Firmar el challenge con la clave privada (recuperada y descifrada)
            const signature = await this.signChallenge(challenge);

            // 3. Enviar la firma al servidor para verificación
            const validationResult = await this.verifySignature(challenge, signature);

            if (validationResult.success) {
                console.log("Autenticación completada con éxito.");
            } else {
                 console.warn("Autenticación fallida:", validationResult.error || "El servidor rechazó la firma.");
            }

            return validationResult; // Devuelve la respuesta del servidor ({success: boolean, ...})
        } catch (error) {
            console.error('Error en el proceso de autenticación completo:', error);
            // Si el error fue por no poder descifrar la clave, informar al usuario podría ser útil.
            if (error.message.includes("descifrar la clave privada")) {
                 alert("No se pudo acceder a la clave guardada. ¿Quizás el Device ID cambió o los datos están corruptos?");
            }
            throw error; // Re-lanzar para manejo externo si es necesario
        }
    }

    // --- Helper Functions ---

    /**
     * Convierte un ArrayBuffer a una cadena Base64 URL Safe
     * @param {ArrayBuffer} buffer - El buffer a convertir
     * @returns {string} Cadena en formato Base64 URL Safe
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        // Convertir a Base64 y hacerlo URL safe
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, ''); // Quitar padding
    }

    /**
     * Convierte una cadena Base64 URL Safe a ArrayBuffer
     * @param {string} base64 - Cadena en formato Base64 URL Safe
     * @returns {ArrayBuffer} El buffer resultante
     */
    base64ToArrayBuffer(base64) {
         // Reemplazar caracteres URL safe y añadir padding si es necesario
        let base64Standard = base64.replace(/-/g, '+').replace(/_/g, '/');
        while (base64Standard.length % 4) {
            base64Standard += '=';
        }
        const binaryString = atob(base64Standard);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Elimina la credencial local (deviceId y clave privada cifrada)
     */
    clearLocalCredentials() {
        localStorage.removeItem("frequentDeviceId");
        localStorage.removeItem("frequentDevicePrivateKey_enc");
        localStorage.removeItem("frequentDevicePublicKey");
        this.deviceId = null;
        this.publicKey = null;
        console.log("Credenciales locales eliminadas.");
    }
}

// Ejemplo de cómo usarlo (esto iría en tu script principal de la página)
/*
async function exampleUsage() {
    const client = new FrequentDeviceWebCryptoClient('/api'); // Ajusta la URL base de tu API

    try {
        // Intentar autenticar directamente si ya está registrado
        const isAuthenticated = await client.checkForExistingCredential();
        if (isAuthenticated) {
            console.log("Credencial encontrada, intentando autenticar...");
            const authResult = await client.authenticate();
            if (authResult.success) {
                alert("Autenticación exitosa!");
                // Proceder con la sesión de usuario
            } else {
                alert("Fallo la autenticación: " + (authResult.error || "Razón desconocida"));
                // Quizás ofrecer registrar de nuevo
                console.log("Ofreciendo registrar de nuevo...");
                await client.clearLocalCredentials(); // Limpiar credenciales viejas/inválidas
                const enrollResult = await client.registerDevice();
                 if (enrollResult.success) {
                    alert("Dispositivo registrado de nuevo con éxito.");
                 } else {
                    alert("Fallo al registrar el dispositivo: " + (enrollResult.error || ""));
                 }
            }
        } else {
            // No hay credencial, registrar el dispositivo
            console.log("No hay credencial local, registrando dispositivo...");
            const enrollResult = await client.registerDevice();
            if (enrollResult.success) {
                alert("Dispositivo registrado con éxito!");
                // Podrías intentar autenticar inmediatamente después si quieres
                // const authResult = await client.authenticate();
                // console.log("Resultado de autenticación post-registro:", authResult);
            } else {
                alert("Fallo al registrar el dispositivo: " + (enrollResult.error || "Razón desconocida"));
            }
        }

    } catch (error) {
        console.error("Error general:", error);
        alert("Ocurrió un error: " + error.message);
    }
}

// Llamar a la función de ejemplo cuando sea apropiado (ej. al cargar la página o al hacer clic en un botón)
// window.addEventListener('load', exampleUsage);
*/ // <-- ADD CLOSING COMMENT MARKER
