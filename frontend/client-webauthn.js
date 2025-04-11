/**
 * Cliente FIDO2 para autenticación de dispositivos frecuentes
 * Se encarga de la generación de claves, firma de desafíos y comunicación con el servidor
 */

// Importar el generador de DeviceID
import { generateDeviceId } from './TrustDeviceGenerator.js';
// Importar la clase base
import { FrequentDeviceClient } from './frequent-device-client-interface.js';

/**
 * Clase para manejar la autenticación de dispositivos frecuentes
 */
export class FrequentDeviceWebAuthnClient extends FrequentDeviceClient {
    constructor(serverUrl = '/api') {
        super(serverUrl); // Llama al constructor de la clase base
        // Cargar valores específicos de WebAuthn desde localStorage
        this.deviceId = localStorage.getItem("webAuthnDeviceId") || this.deviceId;
        this.credentialId = localStorage.getItem("webAuthnCredentialId") || null;
        // publicKey se maneja dinámicamente
    }

    /**
     * Ensures a Device ID exists, generating one if necessary.
     * @returns {Promise<string>} The Device ID.
     */
    async ensureDeviceId() {
        if (!this.deviceId) {
            console.log("Generando nuevo Device ID (WebAuthn)... ");
            try {
                // Generate a new Device ID using the imported function
                this.deviceId = await generateDeviceId();
                // Store it for persistence
                localStorage.setItem("webAuthnDeviceId", this.deviceId);
            } catch (error) {
                console.error('Error al generar Device ID (WebAuthn):', error);
                throw error;
            }
        }

        // Attempt to load the existing public key if the deviceId was found
        if (localStorage.getItem("webAuthnDeviceId") === this.deviceId) { // Check if we are using an existing ID
            const storedPublicKey = localStorage.getItem("webAuthnPublicKey");
            if (storedPublicKey) {
                try {
                    this.publicKey = JSON.parse(storedPublicKey);
                    console.log("ensureDeviceId: Clave pública existente cargada en el cliente.");
                } catch (e) {
                    console.error("ensureDeviceId: Error al parsear la clave pública almacenada:", e);
                    // Clear potentially corrupted keys if parsing fails
                    localStorage.removeItem("webAuthnPublicKey");
                    localStorage.removeItem("webAuthnCredentialId");
                    this.publicKey = null; // Reset client state
                    console.warn("ensureDeviceId: Claves almacenadas eliminadas debido a error de parsing.");
                }
            } else {
                // Device ID exists, but public key doesn't. This indicates an incomplete registration.
                console.log("ensureDeviceId: Device ID encontrado, pero no la clave pública. Se requiere registro.");
                this.publicKey = null; // Ensure client state reflects missing key
            }
        }

        return this.deviceId;
    }

    /**
     * Verifica si ya existe una credencial WebAuthn (ID, clave pública, ID de credencial) en localStorage.
     * También carga la clave pública si existe.
     * @returns {Promise<boolean>} True si existe una credencial válida.
     */
    async checkForExistingCredential() {
        await this.ensureDeviceId(); // Asegura que this.deviceId esté cargado
        if (!this.deviceId) {
            console.log("WebAuthnClient.checkForExistingCredential: No deviceId found.");
            return false;
        }

        const storedCredentialId = localStorage.getItem("webAuthnCredentialId");
        const storedPublicKey = localStorage.getItem("webAuthnPublicKey");

        if (storedCredentialId && storedPublicKey) {
            console.log("WebAuthnClient.checkForExistingCredential: Found stored credential ID and public key.");
            try {
                // Load the public key if it was stored (usually it might not be needed directly for WebAuthn get)
                this.publicKey = JSON.parse(storedPublicKey); 
                console.log("WebAuthnClient.checkForExistingCredential: Public key loaded into client instance.");
                return true; // Indicate that essential credentials exist
            } catch (e) {
                console.error("WebAuthnClient.checkForExistingCredential: Error parsing stored public key:", e);
                // Consider corrupted state, clear keys
                this.clearLocalCredentials(); 
                return false;
            }
        } else {
            console.log("WebAuthnClient.checkForExistingCredential: Missing stored keys (CredentialID exists?", !!storedCredentialId, ", PublicKey exists?", !!storedPublicKey, ")");
            // Ensure client state is clean if keys are missing
            this.publicKey = null; 
            return false;
        }
    }

    /**
     * Genera un par de claves criptográficas para el dispositivo usando WebAuthn
     * @returns {Promise<PublicKeyCredential>} Objeto con las credenciales generadas
     */
    async generateKeyPair() {
        try {
            if (!this.deviceId) {
                throw new Error('Se requiere un deviceId antes de generar claves');
            }
            
            // Crear un nombre de usuario basado en el deviceId
            const username = `device_${this.deviceId.substring(0, 8)}`;
            
            // Crear opciones para la creación de credenciales WebAuthn
            const publicKeyCredentialCreationOptions = {
                challenge: window.crypto.getRandomValues(new Uint8Array(32)),
                rp: {
                    name: 'Santander Dispositivos Frecuentes',
                    id: window.location.hostname
                },
                user: {
                    id: new TextEncoder().encode(this.deviceId),
                    name: username,
                    displayName: 'Dispositivo Frecuente'
                },
                pubKeyCredParams: [
                    { type: 'public-key', alg: -7 }, // ES256
                    { type: 'public-key', alg: -257 } // RS256
                ],
                timeout: 60000, // 1 minuto
                attestation: 'none',
                authenticatorSelection: {
                    authenticatorAttachment: 'platform',
                    userVerification: 'discouraged',
                    requireResidentKey: false
                }
            };
            
            // Crear la credencial
            const credential = await navigator.credentials.create({
                publicKey: publicKeyCredentialCreationOptions
            });
            
            // Registrar información para depuración
            console.log('Credencial WebAuthn creada:', credential);
            console.log('ID de credencial:', credential.id);
            console.log('Tipo de credencial:', credential.type);
            console.log('Client Data JSON:', this.arrayBufferToBase64(credential.response.clientDataJSON));
            console.log('Attestation Object:', this.arrayBufferToBase64(credential.response.attestationObject));
            
            // Guardar el ID de credencial como publicKey para mantener compatibilidad con la interfaz
            this.publicKey = {
                kid: credential.id,
                alg: 'RS256',
                kty: 'RSA'
                // Nota: No podemos extraer la clave pública real con WebAuthn
                // Solo obtenemos un identificador de credencial
            };
            
            // Devolver la credencial completa para que registerDevice pueda enviarla al servidor
            return credential;
            this.publicKey = publicKeyJwk;
            
            // Guardar el ID de credencial en localStorage
            localStorage.setItem('webAuthnCredentialId', credentialId);
            
            return {
                publicKey: this.publicKey,
                credentialId: credentialId
            };
        } catch (error) {
            console.error('Error al generar claves con WebAuthn:', error);
            throw error;
        }
    }

    /**
     * Método mantenido por compatibilidad con la interfaz original
     * En WebAuthn no almacenamos directamente una clave privada
     * @returns {Promise<boolean>} True si se almacenó correctamente
     */
    async storePrivateKey() {
        try {
            // En WebAuthn, la clave privada nunca sale del dispositivo
            // El ID de credencial ya se almacena en localStorage durante generateKeyPair
            // Este método se mantiene por compatibilidad con la interfaz original
            
            if (!this.deviceId) {
                throw new Error('Se requiere deviceId para el almacenamiento');
            }
            
            const credentialId = localStorage.getItem('webAuthnCredentialId');
            if (!credentialId) {
                console.warn('No hay credencial WebAuthn para almacenar. Debe generar claves primero.');
                return false;
            }
            
            return true;
        } catch (error) {
            console.error('Error en storePrivateKey con WebAuthn:', error);
            throw error;
        }
    }

    /**
     * Método mantenido por compatibilidad con la interfaz original
     * En WebAuthn no necesitamos cifrar una clave privada, ya que nunca sale del dispositivo
     * @param {Object} privateKey - Parámetro mantenido por compatibilidad
     * @param {string} password - Parámetro mantenido por compatibilidad
     * @returns {Promise<Object>} Objeto vacío para mantener compatibilidad
     */
    async encryptPrivateKey(privateKey, password) {
        // En WebAuthn, la clave privada nunca sale del dispositivo
        // Este método se mantiene por compatibilidad con la interfaz original
        console.log('encryptPrivateKey llamado, pero no es necesario en WebAuthn');
        return {};
    }

    /**
     * Recupera el ID de credencial WebAuthn almacenado
     * @param {string} customPassword - Parámetro mantenido por compatibilidad pero no usado en WebAuthn
     * @returns {Promise<string>} ID de la credencial WebAuthn
     */
    async retrievePrivateKey(customPassword = null) {
        try {
            // En WebAuthn no recuperamos directamente una clave privada
            // En su lugar, recuperamos el ID de la credencial para usarlo en operaciones de firma
            const credentialId = localStorage.getItem('webAuthnCredentialId');
            
            if (!credentialId) {
                throw new Error('No se encontró ninguna credencial WebAuthn almacenada');
            }
            
            return credentialId;
        } catch (error) {
            console.error('Error al recuperar credencial WebAuthn:', error);
            throw error;
        }
    }

    /**
     * Registra el dispositivo en el servidor usando WebAuthn
     * @returns {Promise<Object>} Respuesta del servidor
     */
    async registerDevice() {
        try {
            if (!this.deviceId) {
                throw new Error('Se requiere generar un deviceId antes de registrar');
            }

            // Generar un par de claves WebAuthn y obtener la credencial completa
            const credential = await this.generateKeyPair();
            
            if (!credential) {
                throw new Error('No se pudo generar la credencial WebAuthn');
            }
            
            // Guardar el ID de credencial para uso futuro
            localStorage.setItem('webAuthnCredentialId', credential.id);
            
            // Preparar los datos de la credencial para enviar al servidor
            // Convertir ArrayBuffers a base64 para poder enviarlos como JSON
            const credentialData = {
                id: credential.id,
                rawId: this.arrayBufferToBase64(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: this.arrayBufferToBase64(credential.response.clientDataJSON),
                    attestationObject: this.arrayBufferToBase64(credential.response.attestationObject),
                }
            };
            
            console.log('Enviando credencial al servidor:', credentialData);
            
            // Enviar al servidor
            const response = await fetch(`${this.serverUrl}/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    deviceId: this.deviceId,
                    credential: credentialData,
                    timestamp: new Date().toISOString(),
                    userAgent: navigator.userAgent,
                    authenticationType: 'webauthn'
                })
            });

            const data = await response.json();
            if (!data.success) {
                throw new Error(data.error || 'Error al registrar el dispositivo con WebAuthn');
            }
            
            console.log('Dispositivo WebAuthn registrado exitosamente:', data);

            return data;
        } catch (error) {
            console.error('Error al registrar dispositivo con WebAuthn:', error);
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
     * Firma un challenge con WebAuthn
     * @param {string} challenge - El challenge a firmar
     * @param {string} customPassword - Parámetro mantenido por compatibilidad pero no usado en WebAuthn
     * @returns {Promise<string>} La firma en formato base64
     */
    async signChallenge(challenge, customPassword = null) {
        try {
            // Recuperar el ID de credencial almacenado
            const credentialId = await this.retrievePrivateKey();
            
            // Convertir el challenge de string a ArrayBuffer
            const challengeBuffer = this.base64ToArrayBuffer(challenge);
            
            // Convertir el ID de credencial a ArrayBuffer
            const credentialIdBuffer = Uint8Array.from(
                atob(credentialId.replace(/-/g, '+').replace(/_/g, '/')), 
                c => c.charCodeAt(0)
            );
            
            // Crear opciones para la solicitud de firma
            const options = {
                challenge: challengeBuffer,
                rpId: window.location.hostname,
                timeout: 60000, // 1 minuto
                allowCredentials: [{
                    id: credentialIdBuffer,
                    type: 'public-key',
                    transports: ['internal']
                }],
                userVerification: 'preferred'
            };
            
            // Solicitar la firma mediante WebAuthn
            const credential = await navigator.credentials.get({
                publicKey: options
            });
            
            // Extraer la firma y los datos de autenticación
            const authData = credential.response.authenticatorData;
            const signature = credential.response.signature;
            const clientDataJSON = credential.response.clientDataJSON;
            
            // Combinar los datos en un solo objeto y convertirlo a base64
            const result = {
                authenticatorData: this.arrayBufferToBase64(authData),
                signature: this.arrayBufferToBase64(signature),
                clientDataJSON: this.arrayBufferToBase64(clientDataJSON),
                credentialId: credential.id
            };
            
            // Devolver el resultado como una cadena JSON en base64
            return btoa(JSON.stringify(result));
        } catch (error) {
            console.error('Error al firmar challenge con WebAuthn:', error);
            throw error;
        }
    }

    /**
     * Verifica la firma del challenge en el servidor usando WebAuthn
     * @param {string} challenge - El challenge firmado
     * @param {string} signature - La firma en formato base64 (contiene los datos de WebAuthn)
     * @returns {Promise<Object>} Respuesta del servidor
     */
    async verifySignature(challenge, signature) {
        try {
            if (!this.deviceId) {
                throw new Error('Se requiere deviceId para verificar la firma');
            }

            // Recuperar el ID de credencial almacenado
            const credentialId = localStorage.getItem('webAuthnCredentialId');
            if (!credentialId) {
                throw new Error('No se encontró ninguna credencial WebAuthn registrada');
            }

            // En el caso de WebAuthn, la firma ya contiene toda la información necesaria
            // para la verificación, incluyendo authenticatorData, clientDataJSON, etc.
            
            const response = await fetch(`${this.serverUrl}/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    deviceId: this.deviceId,
                    challenge,
                    signature,
                    credentialId,
                    authenticationType: 'webauthn'
                })
            });

            const data = await response.json();
            if (!data.success) {
                throw new Error(data.error || 'Error al verificar la firma con WebAuthn');
            }

            return data;
        } catch (error) {
            console.error('Error al verificar firma con WebAuthn:', error);
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
            
            // Verificar que exista un ID de credencial almacenado
            const credentialId = localStorage.getItem('webAuthnCredentialId');
            if (!credentialId) {
                throw new Error('No se encontró ninguna credencial WebAuthn almacenada');
            }
            
            // Intentar solicitar un challenge al servidor
            // Si el dispositivo no está registrado, esto fallará
            await this.requestChallenge();
            
            // Si llegamos aquí, el dispositivo es válido
            return true;
        } catch (error) {
            console.error('Error al validar dispositivo WebAuthn:', error);
            throw error;
        }
    }

    /**
     * Elimina las credenciales WebAuthn almacenadas en localStorage
     */
    clearLocalCredentials() {
        localStorage.removeItem("webAuthnDeviceId");
        localStorage.removeItem("webAuthnPublicKey");
        localStorage.removeItem("webAuthnCredentialId"); // Asegúrate de limpiar también el ID de credencial
        this.deviceId = null;
        this.publicKey = null;
        console.log("Credenciales WebAuthn locales eliminadas.");
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
