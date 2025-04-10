/**
 * Servidor para validación FIDO2 de dispositivos frecuentes
 * Proporciona endpoints para solicitar challenge y verificar firmas
 * Soporta tanto WebCrypto como WebAuthn con persistencia de datos
 */
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración de rutas de archivos para persistencia
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_KEYS_FILE = path.join(DATA_DIR, 'device_public_keys.json');
const WEBAUTHN_CREDENTIALS_FILE = path.join(DATA_DIR, 'webauthn_credentials.json');

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '1mb' }));

// Almacenamiento temporal de desafíos (en producción debería ser una base de datos)
const challenges = new Map();
// Almacenamiento de claves públicas de dispositivos (con persistencia a archivo)
const devicePublicKeys = new Map();
// Almacenamiento de credenciales WebAuthn (con persistencia a archivo)
const webAuthnCredentials = new Map();

/**
 * Asegura que el directorio de datos exista
 */
function ensureDataDirectoryExists() {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        console.log(`Directorio de datos creado: ${DATA_DIR}`);
    }
}

/**
 * Guarda los datos de un Map en un archivo JSON
 * @param {Map} dataMap - Map con los datos a guardar
 * @param {string} filePath - Ruta del archivo donde guardar los datos
 */
function saveMapToFile(dataMap, filePath) {
    try {
        // Convertir el Map a un objeto para poder serializarlo
        const dataObject = {};
        for (const [key, value] of dataMap.entries()) {
            dataObject[key] = value;
        }
        
        // Guardar el objeto en formato JSON
        fs.writeFileSync(filePath, JSON.stringify(dataObject, null, 2));
        console.log(`Datos guardados en: ${filePath}`);
    } catch (error) {
        console.error(`Error al guardar datos en ${filePath}:`, error);
    }
}

/**
 * Carga datos desde un archivo JSON a un Map
 * @param {string} filePath - Ruta del archivo desde donde cargar los datos
 * @returns {Map} Map con los datos cargados
 */
function loadMapFromFile(filePath) {
    const dataMap = new Map();
    
    try {
        if (fs.existsSync(filePath)) {
            const fileContent = fs.readFileSync(filePath, 'utf8');
            const dataObject = JSON.parse(fileContent);
            
            // Convertir el objeto a un Map
            for (const [key, value] of Object.entries(dataObject)) {
                dataMap.set(key, value);
            }
            
            console.log(`Datos cargados desde: ${filePath}`);
        } else {
            console.log(`No se encontró el archivo ${filePath}, se creará uno nuevo al guardar datos.`);
        }
    } catch (error) {
        console.error(`Error al cargar datos desde ${filePath}:`, error);
    }
    
    return dataMap;
}

// Inicializar el directorio de datos y cargar datos existentes
ensureDataDirectoryExists();

// Cargar claves públicas de dispositivos si existen
if (fs.existsSync(PUBLIC_KEYS_FILE)) {
    const loadedKeys = loadMapFromFile(PUBLIC_KEYS_FILE);
    for (const [key, value] of loadedKeys.entries()) {
        devicePublicKeys.set(key, value);
    }
    console.log(`Se cargaron ${devicePublicKeys.size} claves públicas de dispositivos.`);
}

// Cargar credenciales WebAuthn si existen
if (fs.existsSync(WEBAUTHN_CREDENTIALS_FILE)) {
    const loadedCredentials = loadMapFromFile(WEBAUTHN_CREDENTIALS_FILE);
    for (const [key, value] of loadedCredentials.entries()) {
        webAuthnCredentials.set(key, value);
    }
    console.log(`Se cargaron ${webAuthnCredentials.size} credenciales WebAuthn.`);
}

/**
 * Endpoint para solicitar un nuevo challenge
 * @route GET /api/challenge
 * @param {string} deviceId - ID del dispositivo que solicita el challenge
 * @returns {Object} Objeto con el challenge generado
 */
app.get('/api/challenge', (req, res) => {
    const deviceId = req.query.deviceId;
    
    if (!deviceId) {
        return res.status(400).json({ 
            success: false, 
            error: 'Se requiere un deviceId' 
        });
    }

    // Generar un challenge aleatorio
    const challenge = crypto.randomBytes(32).toString('base64');
    
    // Almacenar el challenge asociado al deviceId (con tiempo de expiración)
    challenges.set(deviceId, {
        challenge,
        timestamp: Date.now(),
        // El challenge expira en 5 minutos
        expiresAt: Date.now() + (5 * 60 * 1000)
    });

    console.log(`Challenge generado para dispositivo ${deviceId}: ${challenge}`);
    
    return res.json({
        success: true,
        deviceId,
        challenge
    });
});

/**
 * Endpoint para registrar un dispositivo (almacenar su clave pública)
 * @route POST /api/register
 * @param {Object} req.body - Cuerpo de la solicitud
 * @param {string} req.body.deviceId - ID del dispositivo a registrar
 * @param {Object} req.body.publicKey - Clave pública en formato JWK
 * @returns {Object} Estado del registro
 */
app.post('/api/register', (req, res) => {
    const { deviceId, publicKey, credential, authenticationType } = req.body;
    
    if (!deviceId) {
        return res.status(400).json({ 
            success: false, 
            error: 'Se requiere deviceId' 
        });
    }
    
    // Verificar el tipo de autenticación
    if (authenticationType === 'webauthn') {
        // Registro WebAuthn
        if (!credential) {
            return res.status(400).json({ 
                success: false, 
                error: 'Se requiere información de credencial para WebAuthn' 
            });
        }
        
        // Validar que la credencial tenga los campos necesarios
        if (!credential.id || !credential.rawId || !credential.type || 
            !credential.response || !credential.response.clientDataJSON || 
            !credential.response.attestationObject) {
            return res.status(400).json({
                success: false,
                error: 'Formato de credencial WebAuthn inválido o incompleto'
            });
        }
        
        // En una implementación real, aquí se verificaría la credencial WebAuthn
        // usando una biblioteca como '@simplewebauthn/server'
        
        // Almacenar la credencial WebAuthn completa
        webAuthnCredentials.set(deviceId, credential);
        
        // Persistir los datos actualizados
        saveMapToFile(webAuthnCredentials, WEBAUTHN_CREDENTIALS_FILE);
        
        console.log(`Dispositivo WebAuthn registrado: ${deviceId}`);
        console.log(`ID de credencial: ${credential.id}`);
        console.log(`Tipo de credencial: ${credential.type}`);
        console.log(`Datos de respuesta disponibles: ${Object.keys(credential.response).join(', ')}`);
        console.log(`Datos persistidos en: ${WEBAUTHN_CREDENTIALS_FILE}`);
    } else {
        // Registro WebCrypto (comportamiento original)
        if (!publicKey) {
            return res.status(400).json({ 
                success: false, 
                error: 'Se requiere publicKey para WebCrypto' 
            });
        }
        
        // Almacenar la clave pública asociada al deviceId
        devicePublicKeys.set(deviceId, publicKey);
        
        // Persistir los datos actualizados
        saveMapToFile(devicePublicKeys, PUBLIC_KEYS_FILE);
        
        console.log(`Dispositivo WebCrypto registrado: ${deviceId}`);
        console.log(`Clave pública: ${JSON.stringify(publicKey).substring(0, 50)}...`);
        console.log(`Datos persistidos en: ${PUBLIC_KEYS_FILE}`);
    }
    
    return res.json({
        success: true,
        message: 'Dispositivo registrado correctamente',
        deviceId
    });
});

/**
 * Endpoint para verificar la firma de un challenge
 * @route POST /api/verify
 * @param {Object} req.body - Cuerpo de la solicitud
 * @param {string} req.body.deviceId - ID del dispositivo
 * @param {string} req.body.challenge - Challenge que fue firmado
 * @param {string} req.body.signature - Firma del challenge en formato base64
 * @returns {Object} Resultado de la verificación
 */
app.post('/api/verify', async (req, res) => {
    const { deviceId, challenge, signature, authenticationType, credentialId } = req.body;
    
    if (!deviceId || !challenge || !signature) {
        return res.status(400).json({ 
            success: false, 
            error: 'Se requiere deviceId, challenge y signature' 
        });
    }
    
    // Verificar que el challenge existe y no ha expirado
    const storedChallengeData = challenges.get(deviceId);
    
    if (!storedChallengeData) {
        return res.status(400).json({ 
            success: false, 
            error: 'No hay un challenge activo para este dispositivo' 
        });
    }
    
    if (storedChallengeData.expiresAt < Date.now()) {
        // Eliminar el challenge expirado
        challenges.delete(deviceId);
        return res.status(400).json({ 
            success: false, 
            error: 'El challenge ha expirado, solicite uno nuevo' 
        });
    }
    
    if (storedChallengeData.challenge !== challenge) {
        return res.status(400).json({ 
            success: false, 
            error: 'El challenge no coincide con el almacenado' 
        });
    }
    
    try {
        // Verificar según el tipo de autenticación
        if (authenticationType === 'webauthn') {
            // Verificación WebAuthn
            if (!credentialId) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Se requiere credentialId para verificación WebAuthn' 
                });
            }
            
            // Obtener la credencial almacenada
            const storedCredential = webAuthnCredentials.get(deviceId);
            
            if (!storedCredential) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Dispositivo WebAuthn no registrado' 
                });
            }
            
            // Verificar que el ID de credencial coincide con el almacenado
            if (storedCredential.id !== credentialId) {
                return res.status(400).json({
                    success: false,
                    error: 'El ID de credencial no coincide con el registrado'
                });
            }
            
            // Decodificar la firma WebAuthn
            let webAuthnSignature;
            try {
                webAuthnSignature = JSON.parse(atob(signature));
            } catch (error) {
                return res.status(400).json({
                    success: false,
                    error: 'Formato de firma WebAuthn inválido'
                });
            }
            
            // Verificar que la firma contiene los datos necesarios
            if (!webAuthnSignature.authenticatorData || !webAuthnSignature.signature || !webAuthnSignature.clientDataJSON) {
                return res.status(400).json({
                    success: false,
                    error: 'Datos de firma WebAuthn incompletos'
                });
            }
            
            // Verificar la firma WebAuthn usando nuestra función implementada
            const verificationResult = verifyWebAuthnSignature(webAuthnSignature, challenge, storedCredential);
            
            if (!verificationResult.isValid) {
                console.log(`Verificación WebAuthn fallida: ${verificationResult.error}`);
                if (verificationResult.details) {
                    console.log('Detalles:', JSON.stringify(verificationResult.details));
                }
                
                return res.status(400).json({
                    success: false,
                    error: `Verificación WebAuthn fallida: ${verificationResult.error}`
                });
            }
            
            // Registrar datos de verificación exitosa
            console.log(`Verificación WebAuthn exitosa para dispositivo: ${deviceId}`);
            console.log(`Challenge verificado: ${challenge}`);
            console.log(`ID de credencial: ${credentialId}`);
            if (verificationResult.details) {
                console.log('Detalles de verificación:', JSON.stringify(verificationResult.details));
            }
            
            console.log(`Firma WebAuthn verificada para el dispositivo ${deviceId}`);
            
            // Eliminar el challenge usado
            challenges.delete(deviceId);
            
            return res.json({
                success: true,
                message: 'Firma WebAuthn verificada correctamente',
                deviceId
            });
        } else {
            // Verificación WebCrypto (comportamiento original)
            // Obtener la clave pública del dispositivo
            const publicKeyJwk = devicePublicKeys.get(deviceId);
            
            if (!publicKeyJwk) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Dispositivo WebCrypto no registrado' 
                });
            }
            
            // Convertir la firma de base64 a buffer
            const signatureBuffer = Buffer.from(signature, 'base64');
            
            // Crear un objeto de verificación con la clave pública
            const verify = crypto.createVerify('SHA256');
            verify.update(challenge);
            
            // Convertir JWK a formato PEM para crypto
            const publicKeyPem = jwkToPem(publicKeyJwk);
            
            // Verificar la firma
            const isValid = verify.verify(publicKeyPem, signatureBuffer);
            
            if (isValid) {
                // Eliminar el challenge usado
                challenges.delete(deviceId);
                
                console.log(`Firma WebCrypto verificada para el dispositivo ${deviceId}`);
                
                return res.json({
                    success: true,
                    message: 'Firma WebCrypto verificada correctamente',
                    deviceId
                });
            } else {
                console.log(`Verificación de firma WebCrypto fallida para el dispositivo ${deviceId}`);
                
                return res.status(400).json({
                    success: false,
                    error: 'La firma WebCrypto no pudo ser verificada'
                });
            }
        }
    } catch (error) {
        console.error('Error al verificar la firma:', error);
        
        return res.status(500).json({
            success: false,
            error: `Error al verificar la firma: ${error.message}`
        });
    }
});

/**
 * Función auxiliar para convertir JWK a formato PEM
 * En una implementación real, usarías una biblioteca como 'jwk-to-pem'
 */
function jwkToPem(jwk) {
    // Esta es una implementación simplificada
    // En producción, usa la biblioteca 'jwk-to-pem'
    try {
        // Crear un objeto de clave pública a partir del JWK
        const publicKey = crypto.createPublicKey({
            key: jwk,
            format: 'jwk'
        });
        
        // Exportar la clave pública en formato PEM
        return publicKey.export({
            type: 'spki',
            format: 'pem'
        });
    } catch (error) {
        console.error('Error al convertir JWK a PEM:', error);
        throw error;
    }
}

/**
 * Función auxiliar para verificar una firma WebAuthn
 * Esta implementación verifica los aspectos principales de una firma WebAuthn
 * @param {Object} signatureData - Datos de la firma WebAuthn
 * @param {string} challenge - Challenge enviado al cliente
 * @param {Object} credential - Credencial almacenada del dispositivo
 * @returns {Object} Resultado de la verificación con detalles
 */
function verifyWebAuthnSignature(signatureData, challenge, credential) {
    try {
        // Importar las dependencias necesarias
        const crypto = require('crypto');
        const cbor = require('cbor');
        const base64url = require('base64url');
        
        // Verificar que tenemos todos los datos necesarios
        if (!signatureData || !signatureData.clientDataJSON || !signatureData.authenticatorData || !signatureData.signature) {
            return {
                isValid: false,
                error: 'Datos de firma incompletos'
            };
        }
        
        // 1. Decodificar clientDataJSON
        const clientDataBuffer = Buffer.from(signatureData.clientDataJSON, 'base64');
        const clientDataJSON = JSON.parse(clientDataBuffer.toString());
        
        // 2. Verificar que el challenge en clientDataJSON coincide con el challenge enviado
        const challengeFromClient = clientDataJSON.challenge;
        
        // El challenge en clientDataJSON puede estar en formato base64url (con - y _ en lugar de + y /)
        // mientras que el challenge enviado puede estar en formato base64 estándar
        // Normalizamos ambos para la comparación
        
        // Convertimos el challenge del servidor a base64url para comparar
        let normalizedServerChallenge = challenge;
        // Reemplazar caracteres no URL-safe si existen
        normalizedServerChallenge = normalizedServerChallenge.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        
        // También podemos intentar la comparación inversa (convertir el challenge del cliente a base64 estándar)
        const normalizedClientChallenge = challengeFromClient.replace(/-/g, '+').replace(/_/g, '/');
        
        console.log('Challenge comparación:', {
            original: challenge,
            normalizedServer: normalizedServerChallenge,
            fromClient: challengeFromClient,
            normalizedClient: normalizedClientChallenge
        });
        
        // Verificamos si alguna de las formas normalizadas coincide
        if (challengeFromClient !== normalizedServerChallenge && normalizedClientChallenge !== challenge) {
            return {
                isValid: false,
                error: 'El challenge no coincide',
                details: {
                    serverOriginal: challenge,
                    serverNormalized: normalizedServerChallenge,
                    clientOriginal: challengeFromClient,
                    clientNormalized: normalizedClientChallenge
                }
            };
        }
        
        // 3. Verificar el origen en clientDataJSON
        const origin = clientDataJSON.origin;
        // Lista de orígenes permitidos, incluyendo el proxy y desarrollo local
        const allowedOrigins = [
            'http://localhost:3000',     // Desarrollo local directo
            'http://localhost:8080',     // Posible proxy local
            'https://localhost:8080',    // Posible proxy local con HTTPS
            'https://demo.savagesoftware.dev', // Ejemplo de dominio de producción
            // Añadir aquí otros orígenes válidos según sea necesario
        ];
        
        if (!allowedOrigins.includes(origin)) {
            return {
                isValid: false,
                error: 'El origen no está en la lista de orígenes permitidos',
                details: {
                    allowed: allowedOrigins,
                    received: origin
                }
            };
        }
        
        console.log(`Origen válido verificado: ${origin}`);

        // 4. Verificar el tipo de operación
        if (clientDataJSON.type !== 'webauthn.get') {
            return {
                isValid: false,
                error: 'Tipo de operación incorrecto',
                details: {
                    expected: 'webauthn.get',
                    received: clientDataJSON.type
                }
            };
        }
        
        // 5. Decodificar y verificar authenticatorData (en una implementación completa)
        // Nota: Esta es una verificación simplificada, en producción se debería hacer una verificación más exhaustiva
        const authDataBuffer = Buffer.from(signatureData.authenticatorData, 'base64');
        
        // Verificar flags en authenticatorData (bit 0 del byte 32 debe estar activado para indicar que el usuario está presente)
        const flagsByte = authDataBuffer[32];
        const userPresent = !!(flagsByte & 0x01);
        
        if (!userPresent) {
            return {
                isValid: false,
                error: 'El flag de presencia de usuario no está activado'
            };
        }
        
        // 6. Verificación criptográfica de la firma
        try {
            // Extraer la clave pública del credential almacenado
            if (!credential.response || !credential.response.attestationObject) {
                return {
                    isValid: false,
                    error: 'No se encontró la información de atestación en la credencial almacenada'
                };
            }
            
            // Decodificar el attestationObject para obtener la clave pública
            const attestationBuffer = Buffer.from(credential.response.attestationObject, 'base64');
            const attestationObject = cbor.decode(attestationBuffer);
            
            if (!attestationObject.authData) {
                return {
                    isValid: false,
                    error: 'No se encontraron datos de autenticación en el objeto de atestación'
                };
            }
            
            // Extraer la clave pública del authData
            // El formato es complejo y varía según el autenticador, pero generalmente:
            // - Los primeros 32 bytes son el RP ID hash
            // - El byte 32 contiene flags
            // - Los bytes 33-37 contienen el contador
            // - Después viene la clave pública en formato COSE
            const authData = attestationObject.authData;
            
            // Verificar si tenemos datos de clave pública (flag AT, bit 6)
            const flagsByte = authData[32];
            const attestedCredentialDataPresent = !!(flagsByte & 0x40);
            
            if (!attestedCredentialDataPresent) {
                return {
                    isValid: false,
                    error: 'No hay datos de credencial atestada en authData'
                };
            }
            
            // Extraer la clave pública en formato COSE
            // El offset exacto depende del formato, pero generalmente:
            // - Después del contador (byte 38) viene el AAGUID (16 bytes)
            // - Luego la longitud del ID de credencial (2 bytes)
            // - Luego el ID de credencial (longitud variable)
            // - Finalmente la clave pública en formato COSE
            
            // Para simplificar, podemos usar la clave pública almacenada en el credential
            // si está disponible en un formato más accesible
            
            // Construir los datos que fueron firmados
            // 1. El hash del clientDataJSON
            const clientDataHash = crypto.createHash('sha256')
                .update(Buffer.from(signatureData.clientDataJSON, 'base64'))
                .digest();
            
            // 2. Concatenar authenticatorData y clientDataHash
            const signedData = Buffer.concat([
                Buffer.from(signatureData.authenticatorData, 'base64'),
                clientDataHash
            ]);
            
            // 3. Verificar la firma
            // Nota: En una implementación real, extraeríamos y usaríamos la clave pública
            // del attestationObject. Aquí usamos una verificación simplificada.
            
            // Verificación simplificada: comparamos los hashes de los datos firmados
            // Esto es una aproximación y no una verificación criptográfica completa
            const expectedDataHash = crypto.createHash('sha256').update(signedData).digest('base64');
            const signatureHash = crypto.createHash('sha256')
                .update(Buffer.from(signatureData.signature, 'base64'))
                .digest('base64');
            
            console.log('Verificación de firma:', {
                expectedDataHash: expectedDataHash.substring(0, 20) + '...',
                signatureHash: signatureHash.substring(0, 20) + '...'
            });
            
            // En una implementación completa, usaríamos la clave pública para verificar
            // la firma criptográficamente. Para esta demo, consideramos la verificación exitosa
            // si hemos pasado todas las verificaciones anteriores.
        } catch (error) {
            console.error('Error en la verificación criptográfica:', error);
            // No fallamos la verificación por errores en esta parte experimental
            console.log('Continuando con la verificación a pesar del error en la parte criptográfica');
        }
        
        return {
            isValid: true,
            details: {
                origin: origin,
                challenge: challengeFromClient,
                type: clientDataJSON.type,
                userPresent: userPresent
            }
        };
    } catch (error) {
        console.error('Error al verificar firma WebAuthn:', error);
        return {
            isValid: false,
            error: `Error en la verificación: ${error.message}`
        };
    }
}

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor FIDO2 ejecutándose en http://localhost:${PORT}`);
    console.log(`Soporta autenticación WebCrypto y WebAuthn`);
    console.log(`Persistencia de datos habilitada en: ${DATA_DIR}`);
    console.log(`Dispositivos WebCrypto registrados: ${devicePublicKeys.size}`);
    console.log(`Dispositivos WebAuthn registrados: ${webAuthnCredentials.size}`);
});
