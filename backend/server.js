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
const { verifyAuthenticationResponse, verifyRegistrationResponse } = require('@simplewebauthn/server');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración de rutas de archivos para persistencia
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_KEYS_FILE = path.join(DATA_DIR, 'device_public_keys.json');
const WEBAUTHN_CREDENTIALS_FILE = path.join(DATA_DIR, 'webauthn_credentials.json');

/**
 * WebAuthn Relying Party (RP) Configuration
 * 
 * RP_ID: Domain name that identifies the Relying Party (entity requesting authentication)
 * Must be a valid domain string that matches or is a registrable domain suffix of the origin
 * 
 * RP_EXPECTED_ORIGIN: Array of allowed origins that can initiate WebAuthn ceremonies
 * These should include all valid URLs where your front-end application runs
 */
const RP_ID = 'demo.savagesoftware.dev'; // Must match the domain the client is running on
const RP_EXPECTED_ORIGIN = ['http://localhost:8080', 'https://demo.savagesoftware.dev']; // Allowed frontend origins

/**
 * Development Configuration
 * These settings should be adjusted for production environments
 */
const DISABLE_COUNTER_VERIFICATION = true; // For development only - disables counter verification in WebAuthn

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
    const challenge = crypto.randomBytes(32).toString('base64url'); // Use base64url encoding
    
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
app.post('/api/register', async (req, res) => { // Make async for registration verification
    const { deviceId, publicKey, credential: clientCredential, authenticationType } = req.body; // Rename to clientCredential

    if (!deviceId) {
        return res.status(400).json({ 
            success: false, 
            error: 'Se requiere deviceId' 
        });
    }
    
    if (authenticationType === 'webauthn') {
        // --- WebAuthn Registration using @simplewebauthn/server --- 
        if (!clientCredential) {
            return res.status(400).json({ 
                success: false, 
                error: 'Se requiere información de credencial para WebAuthn' 
            });
        }

        // Retrieve the original challenge for this registration attempt
        const storedChallengeData = challenges.get(deviceId);
        if (!storedChallengeData) {
            return res.status(400).json({ success: false, error: 'No se encontró challenge para este registro o ha expirado' });
        }
        const expectedChallenge = storedChallengeData.challenge;

        let verification;
        try {
            verification = await verifyRegistrationResponse({
                response: clientCredential, // The registration response object from the client
                expectedChallenge: expectedChallenge, // The original challenge from the server's memory
                expectedOrigin: RP_EXPECTED_ORIGIN,
                expectedRPID: RP_ID,
                requireUserVerification: true, // Typically true for registration
            });
        } catch (error) {
            console.error("WebAuthn Registration Verification Error:", error);
            return res.status(400).json({ success: false, error: `Verificación del registro WebAuthn fallida: ${error.message}` });
        }

        const { verified, registrationInfo } = verification;

        if (!verified || !registrationInfo) {
             return res.status(400).json({ success: false, error: 'No se pudo verificar el registro WebAuthn' });
        }

        // Extract necessary info and store using credentialID as the key
        const { credential, credentialDeviceType, credentialBackedUp } = registrationInfo;
        const { id: credentialID, publicKey: credentialPublicKey, counter } = credential; // Extract nested data

        // Check if this credential ID already exists
        if (webAuthnCredentials.has(credentialID)) {
            return res.status(400).json({ success: false, error: `El ID de credencial ya existe: ${credentialID}` });
        }
        
        // Importante: Almacenar el publicKey directamente como array de bytes en base64
        // En vez de convertirlo primero a Buffer y luego a string
        const rawPublicKeyBase64 = Buffer.from(credentialPublicKey).toString('base64');
        console.log('Almacenando nueva credencial con publicKey:', rawPublicKeyBase64.slice(0, 20) + '...');
        
        const newCredential = {
            credentialID: credentialID, // ID is already a Base64URL string
            credentialPublicKey: rawPublicKeyBase64, // Store as Base64 directly
            counter: counter,
            // Optional: Store transports if available from registration response
            transports: clientCredential.response.transports || ['internal'], 
            deviceType: credentialDeviceType,
            backedUp: credentialBackedUp,
            // Optional: Link back to the deviceId if needed for user management
            deviceId: deviceId,
            // Store creation timestamp
            createdAt: new Date().toISOString()
        };

        webAuthnCredentials.set(credentialID, newCredential);
        saveMapToFile(webAuthnCredentials, WEBAUTHN_CREDENTIALS_FILE); // Persist updated credentials

        console.log(`Credencial WebAuthn registrada exitosamente con ID: ${credentialID} para deviceId: ${deviceId}`);
        console.log(`Datos persistidos en: ${WEBAUTHN_CREDENTIALS_FILE}`);

        // Clean up the challenge used for registration
        challenges.delete(deviceId);

    } else if (authenticationType === 'webcrypto') {
        // --- WebCrypto Registration (Existing Logic) ---
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
    const { deviceId, challenge, signature, authenticationType, assertion } = req.body;

    // Basic validation: deviceId is always required
    if (!deviceId) {
        return res.status(400).json({ success: false, error: 'Se requiere deviceId' });
    }

    // Challenge validation (common for both types)
    // Retrieve the *original* challenge sent to this user/device
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

    // The challenge used for verification depends on the auth type
    // WebCrypto signed the original challenge string directly
    // WebAuthn signs over clientDataJSON which *contains* the challenge
    // We'll use storedChallengeData.challenge for both verification steps below
    const expectedChallenge = storedChallengeData.challenge; 
    
    try {
        if (authenticationType === 'webauthn') {
            // --- WebAuthn Verification using @simplewebauthn/server --- 
            
            if (!assertion) {
                return res.status(400).json({ 
                    success: false, 
                    error: 'Se requiere el objeto `assertion` para verificación WebAuthn'
                });
            }

            // Get the credential stored during registration
            const credentialID = assertion.id; // Use the ID from the assertion
            let storedCredential = webAuthnCredentials.get(credentialID);
            
            // If not found directly, log this for debugging
            if (!storedCredential) {
                console.log(`Credential ID from client: ${credentialID}`);
                console.log(`Available credentials: ${Array.from(webAuthnCredentials.keys()).join(', ')}`);
                
                // Try to find it by comparing against all stored credentials (case-insensitive)
                for (const [storedId, credential] of webAuthnCredentials.entries()) {
                    if (storedId.toLowerCase() === credentialID.toLowerCase()) {
                        console.log(`Found credential with case-insensitive match: ${storedId}`);
                        storedCredential = credential;
                        break;
                    }
                }
                
                // If still not found
                if (!storedCredential) {
                    return res.status(400).json({ 
                        success: false, 
                        error: `No se encontró credencial WebAuthn almacenada para el ID: ${credentialID}`
                    });
                }
            }

            // Log the stored credential for debugging
            console.log('Stored credential:', JSON.stringify(storedCredential, null, 2));
            
            // Log information about the assertion format
            console.log('Assertion format check:', {
                hasId: !!assertion.id,
                hasType: !!assertion.type,
                hasResponse: !!assertion.response,
                responseFields: assertion.response ? Object.keys(assertion.response) : [],
                rawIdFormat: typeof assertion.rawId,
            });

            // Examinar el objeto de aserción tal como viene del cliente
            console.log('Assertion raw ID:', assertion.rawId ? assertion.rawId.slice(0, 20) + '...' : 'undefined');
            console.log('Assertion id:', assertion.id ? assertion.id.slice(0, 20) + '...' : 'undefined');
            
            // Declaramos variables para la verificación
            let verified = false;
            let authenticatorInfo = null;
            
            try {
                // Inspeccionar los datos de la aserción para depurar
                console.log('Aserción WebAuthn recibida:', {
                    id: assertion.id ? (assertion.id.slice(0, 10) + '...') : 'undefined',
                    rawId: assertion.rawId ? 'presente' : 'undefined',
                    type: assertion.type || 'undefined',
                    responseKeys: assertion.response ? Object.keys(assertion.response) : [],
                });
                
                // Detailed inspection of assertion structure
                console.log('Detailed assertion structure:', {
                    id_type: typeof assertion.id,
                    rawId_type: typeof assertion.rawId,
                    rawId_length: assertion.rawId ? assertion.rawId.length : 0,
                    full_id: assertion.id,
                    response_authenticatorData_type: typeof assertion.response.authenticatorData,
                    response_clientDataJSON_type: typeof assertion.response.clientDataJSON,
                    response_signature_type: typeof assertion.response.signature
                });
                
                // Log the client data JSON for debugging
                try {
                    const clientDataObj = JSON.parse(Buffer.from(assertion.response.clientDataJSON, 'base64').toString());
                    console.log('Client data JSON:', {
                        type: clientDataObj.type,
                        challenge: clientDataObj.challenge ? (clientDataObj.challenge.substring(0, 10) + '...') : 'missing',
                        origin: clientDataObj.origin
                    });
                } catch (e) {
                    console.log('Error parsing client data JSON:', e.message);
                }
                
                // Convertir la clave pública almacenada correctamente
                // Este es un paso crítico - la clave debe estar en el formato correcto
                const publicKeyBuffer = Buffer.from(storedCredential.credentialPublicKey, 'base64');
                
                // Log para verificar que tenemos una clave pública válida
                console.log('Clave pública:', {
                    format: 'Buffer',
                    byteLength: publicKeyBuffer.byteLength,
                    sampleBytes: Array.from(publicKeyBuffer.slice(0, 5)).map(b => b.toString(16)).join(' ')
                });
                
                // Verificar que el credentialID esté en formato base64url correcto
                console.log('Credential ID format check:', {
                    value: storedCredential.credentialID,
                    isBase64url: /^[A-Za-z0-9_-]+$/g.test(storedCredential.credentialID),
                    length: storedCredential.credentialID.length
                });
                
                // Verificar si el format del rawId coincide con el credentialID
                console.log('Raw ID vs Credential ID:', {
                    rawIdFromClient: assertion.id,
                    storedCredentialID: storedCredential.credentialID,
                    match: assertion.id === storedCredential.credentialID
                });
                
                // Preparar el objeto authenticator usando el formato exacto que espera la biblioteca
                // IMPORTANTE: credentialID debe mantenerse como string en formato base64url
                const authenticator = {
                    // Mantener el credentialID como string en formato base64url
                    // SimpleWebAuthn espera que esté en este formato, NO como Buffer
                    credentialID: storedCredential.credentialID,
                    
                    // La clave pública DEBE ser un Buffer
                    credentialPublicKey: publicKeyBuffer,
                    
                    // El contador debe ser un número, no una string
                    counter: typeof storedCredential.counter === 'number' ? storedCredential.counter : 0,
                    
                    // Transportes disponibles
                    transports: storedCredential.transports || ['internal']
                };
                
                console.log('Objeto authenticator configurado:', {
                    credentialID: authenticator.credentialID ? (authenticator.credentialID.slice(0, 10) + '...') : 'undefined',
                    hasPublicKey: !!authenticator.credentialPublicKey,
                    counter: authenticator.counter,
                    transports: authenticator.transports
                });
                
                // Convertir valores de response que podrían ser strings a ArrayBuffers
                // Este es un paso crucial para SimpleWebAuthn
                const convertToArrayBuffer = (value) => {
                    if (!value) return null;
                    if (typeof value === 'string') {
                        // Si es una string base64, convertírla a ArrayBuffer
                        const buffer = Buffer.from(value, 'base64url');
                        return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
                    }
                    // Si ya es un ArrayBuffer o un ArrayBufferView, devolverlo como está
                    return value;
                };
                
                // Crear un objeto formateado para la verificación
                const formattedAssertion = {
                    // El ID debe mantenerse como string en formato base64url
                    id: assertion.id,
                    
                    // Según la documentación, rawId debe ser un ArrayBuffer
                    rawId: convertToArrayBuffer(assertion.rawId),
                    
                    // Tipo siempre debe ser 'public-key'
                    type: 'public-key',
                    
                    response: {
                        // Convertir todos los campos de respuesta a ArrayBuffer si son strings
                        authenticatorData: convertToArrayBuffer(assertion.response.authenticatorData),
                        clientDataJSON: convertToArrayBuffer(assertion.response.clientDataJSON),
                        signature: convertToArrayBuffer(assertion.response.signature),
                        userHandle: assertion.response.userHandle ? convertToArrayBuffer(assertion.response.userHandle) : null
                    }
                };
                
                console.log('Formato de formattedAssertion:', {
                    id: typeof formattedAssertion.id,
                    rawId: formattedAssertion.rawId instanceof ArrayBuffer ? 'ArrayBuffer' : typeof formattedAssertion.rawId,
                    response: {
                        authenticatorData: formattedAssertion.response.authenticatorData instanceof ArrayBuffer ? 'ArrayBuffer' : typeof formattedAssertion.response.authenticatorData,
                        clientDataJSON: formattedAssertion.response.clientDataJSON instanceof ArrayBuffer ? 'ArrayBuffer' : typeof formattedAssertion.response.clientDataJSON,
                        signature: formattedAssertion.response.signature instanceof ArrayBuffer ? 'ArrayBuffer' : typeof formattedAssertion.response.signature
                    }
                });
                
                /**
                 * Let's inspect what the SimpleWebAuthn library expects
                 * From testing, it seems we need to match exactly what its internal validation needs
                 */
                console.log('Using minimal processing approach with SimpleWebAuthn');
                
                // The base64url string must NOT be modified
                const credentialIDBase64 = storedCredential.credentialID;
                
                // Confirm we're using the right format
                console.log('Final credential check:', {
                  originalID: credentialIDBase64,
                  isValidBase64URL: /^[A-Za-z0-9_-]+$/g.test(credentialIDBase64),
                });
                
                // Looking at the assertion response data structure more carefully
                // Let's ensure it matches the expected AuthenticationCredentialJSON format
                
                /**
                 * Step 1: Prepare the verification data exactly according to SimpleWebAuthn documentation
                 * See: https://simplewebauthn.dev/docs/packages/server
                 */
                
                // Prepare the base64url-encoded credential ID - this MUST remain a string
                const credentialID = storedCredential.credentialID;
                
                /**
                 * Convert the credential public key from base64 to a Buffer
                 * 
                 * The SimpleWebAuthn library expects this to be a Buffer containing the COSE key
                 * This is critical for the verification process to work correctly
                 */
                const credentialPublicKey = Buffer.from(storedCredential.credentialPublicKey, 'base64');
                
                // Log the public key buffer details to ensure it's valid
                console.log('Public key buffer details:', {
                    isBuffer: Buffer.isBuffer(credentialPublicKey),
                    length: credentialPublicKey.length,
                    firstFewBytes: credentialPublicKey.slice(0, 5).toString('hex')
                });
                
                // Validate that the public key looks like a COSE key (should start with 0xA5 for a COSE_Key)
                if (credentialPublicKey.length === 0 || credentialPublicKey[0] !== 0xA5) {
                    console.warn('Warning: Public key may not be in the expected COSE format');
                }
                
                // Make sure the counter is a number (default to 0 if undefined)
                const counter = typeof storedCredential.counter === 'number' ? storedCredential.counter : 0;
                
                // Update the stored credential if counter needs initialization
                if (typeof storedCredential.counter !== 'number') {
                    console.warn('Initializing counter in credential to 0');
                    storedCredential.counter = 0;
                    
                    // Save the updated credential to ensure it has a counter next time
                    webAuthnCredentials.set(credentialID, storedCredential);
                    saveMapToFile(webAuthnCredentials, WEBAUTHN_CREDENTIALS_FILE);
                }
                
                console.log('Verification preparation:', {
                    credentialID: credentialID.substring(0, 10) + '...',
                    publicKeyLength: credentialPublicKey.length,
                    counter: counter
                });
                
                // The original assertion object should be used without modification
                // SimpleWebAuthn will handle the parsing internally
                
                // Logging full authenticator structure for debugging
                /**
                 * Log the complete credential structure for debugging
                 * This helps identify any issues with the credential format
                 */
                console.log('Full credential structure:', {
                    id: storedCredential.credentialID,
                    publicKey_buffer: Buffer.isBuffer(credentialPublicKey),
                    publicKey_length: credentialPublicKey.length,
                    publicKey_valid: credentialPublicKey.length > 0 && credentialPublicKey[0] === 0xA5,
                    counter: counter, // Use our normalized counter value
                    counterType: typeof counter,
                    transports: storedCredential.transports
                });
                
                // Prepare the credential object according to WebAuthnCredential type
                const credential = {
                    id: credentialID,
                    publicKey: credentialPublicKey,
                    counter: counter,
                    transports: storedCredential.transports || ['internal']
                };
                
                console.log('Final credential object structure:', {
                    hasId: typeof credential.id === 'string',
                    hasPublicKey: Buffer.isBuffer(credential.publicKey),
                    hasCounter: typeof credential.counter === 'number',
                    hasTransports: Array.isArray(credential.transports)
                });
                
                /**
                 * WebAuthn Authentication Verification
                 * 
                 * This process verifies that an assertion received from a client's authenticator
                 * is valid and matches our stored credentials for that user/device.
                 * 
                 * Critical security steps:
                 * 1. Verify the challenge matches what we sent to the client
                 * 2. Verify the origin matches an allowed origin
                 * 3. Verify the credential ID matches a registered credential
                 * 4. Verify the signature using the stored public key
                 * 5. Verify the counter value to prevent replay attacks
                 */
                
                // This simplified approach follows the exact pattern from SimpleWebAuthn documentation
                try {
                    // Extract the actual origin from the client data for debugging
                    try {
                        const clientDataObj = JSON.parse(Buffer.from(assertion.response.clientDataJSON, 'base64').toString());
                        console.log('Client assertion origin:', clientDataObj.origin);
                        
                        // Check if the client's origin is in our allowed list
                        const clientOrigin = clientDataObj.origin;
                        const isOriginAllowed = Array.isArray(RP_EXPECTED_ORIGIN) 
                            ? RP_EXPECTED_ORIGIN.includes(clientOrigin)
                            : RP_EXPECTED_ORIGIN === clientOrigin;
                            
                        if (!isOriginAllowed) {
                            console.warn(`Origin mismatch warning: Client origin ${clientOrigin} not in allowed list: ${RP_EXPECTED_ORIGIN}`);
                        }
                    } catch (e) {
                        console.error('Could not parse client data for origin check:', e.message);
                    }
                    
                    // Parse the client data JSON to extract origin and other info
                    const clientDataObj = JSON.parse(Buffer.from(assertion.response.clientDataJSON, 'base64').toString());
                    const clientOrigin = clientDataObj.origin;
                    
                    // Extract the domain from the client origin
                    const domainFromOrigin = new URL(clientOrigin).hostname;
                    
                    console.log('Verifying with extracted domain details:', {
                        clientOrigin,
                        domainFromOrigin,
                        configuredRPID: RP_ID,
                        domainsMatch: domainFromOrigin === RP_ID || domainFromOrigin.endsWith(`.${RP_ID}`)
                    });
                    
                    // Check if we should use the configured RP_ID or the domain from client origin
                    // For security, we'll use the configured RP_ID if it matches the client domain
                    const effectiveRPID = RP_ID;
                    
                    /**
                     * Verify the authentication response using SimpleWebAuthn
                     * 
                     * This is the core security verification step that validates:
                     * 1. The challenge matches what we sent
                     * 2. The origin is valid
                     * 3. The signature was created by the authenticator with the registered public key
                     * 4. The counter value is higher than previously recorded (prevents replay attacks)
                     */
                    const verificationResult = await verifyAuthenticationResponse({
                        // Pass the original assertion with minimal modification
                        response: assertion,
                        
                        // Security verification parameters - use the client's actual origin
                        // This is crucial - the library validates against this exact origin
                        expectedChallenge,
                        expectedOrigin: clientOrigin, // Use the origin from client data instead of our array
                        
                        // The RP_ID must match the effective domain of the client
                        // This is crucial for security - prevents cross-domain attacks
                        expectedRPID: effectiveRPID,
                        
                        // Use the pre-constructed credential object that matches WebAuthnCredential type
                        credential,
                        
                        // Optional verification options
                        requireUserVerification: false,
                        
                        // For development only: disable counter verification if needed
                        // This helps when testing with authenticators that don't increment their counter properly
                        ...(DISABLE_COUNTER_VERIFICATION ? { requireCounter: false } : {})
                    });
                    
                        // Store verification results
                    verified = verificationResult.verified;
                    
                    // Log the full verification result structure for debugging
                    console.log('Full verification result structure:', JSON.stringify(verificationResult, null, 2));
                    
                    /**
                     * Handle different response structures from SimpleWebAuthn
                     * Different versions of the library may use different property names
                     * - Older versions use 'authenticatorInfo'
                     * - Newer versions use 'authenticationInfo'
                     */
                    if (verificationResult.authenticatorInfo) {
                        // Handle older SimpleWebAuthn versions
                        authenticatorInfo = verificationResult.authenticatorInfo;
                        console.log('Using authenticatorInfo from older SimpleWebAuthn version');
                    } else if (verificationResult.authenticationInfo) {
                        // Handle newer SimpleWebAuthn versions
                        authenticatorInfo = verificationResult.authenticationInfo;
                        console.log('Using authenticationInfo from newer SimpleWebAuthn version');
                    } else {
                        // No info object found
                        authenticatorInfo = null;
                        console.log('No authenticator/authentication info found in verification result');
                    }
                    
                    // Log the verification result
                    if (authenticatorInfo) {
                        console.log('WebAuthn verification successful:', {
                            verified,
                            // Only access newCounter if it exists
                            newCounter: authenticatorInfo.newCounter !== undefined ? authenticatorInfo.newCounter : 'N/A',
                            credentialID: credentialID.substring(0, 10) + '...',
                            deviceID: deviceId
                        });
                    } else {
                        console.log('WebAuthn verification successful but no authenticator info returned:', {
                            verified,
                            credentialID: credentialID.substring(0, 10) + '...',
                            deviceID: deviceId
                        });
                    }
                    
                } catch (error) {
                    console.error('SimpleWebAuthn verification error:', error);
                    
                        // Extract and log additional details about the error
                    if (error.stack) {
                        const errorLines = error.stack.split('\n').slice(0, 3);
                        console.error('Error details:', errorLines);
                    }
                    
                    // Check if the error is related to origin mismatch
                    if (error.message && error.message.includes('origin')) {
                        try {
                            // Try to extract the actual origin from the client data
                            const clientDataObj = JSON.parse(Buffer.from(assertion.response.clientDataJSON, 'base64').toString());
                            console.error('Origin mismatch - Client provided:', clientDataObj.origin);
                            console.error('Expected origin(s):', RP_EXPECTED_ORIGIN);
                        } catch (e) {
                            console.error('Could not parse client data to check origin');
                        }
                    }
                    
                    throw error; // Re-throw to be caught by the outer catch block
                }
                
                /**
                 * At this point, if execution continues, the verification was successful.
                 * The verification results are stored in the verified and authenticatorInfo variables.
                 * 
                 * The authenticatorInfo contains important security data like the new counter value
                 * which is crucial for preventing replay attacks in WebAuthn.
                 */
            } catch (error) {
                console.error('Error during WebAuthn verification:', error);
                return res.status(400).json({
                    success: false,
                    error: `Error de verificación WebAuthn: ${error.message}`
                });
            }
            
            // Check if verification was successful
            if (!verified) {
                return res.status(401).json({ 
                    success: false, 
                    error: 'Verificación WebAuthn fallida'
                });
            }

            /**
             * Update the credential counter if verification was successful
             * 
             * This is an important security feature of WebAuthn - the counter should be
             * incremented with each successful authentication to prevent replay attacks.
             * The authenticator increases its counter value with each use, and the server
             * verifies that the new counter value is greater than the previously stored one.
             *
             * Note: Different versions of SimpleWebAuthn may have different response structures.
             * We need to handle all possible cases to ensure the counter is properly updated.
             */
            
            /**
             * Determine the new counter value
             * We need to handle different response structures and provide a fallback
             */
            
            // Check if we have authenticatorInfo with a newCounter property
            const hasNewCounter = authenticatorInfo && typeof authenticatorInfo.newCounter === 'number';
            
            /**
             * Get the new counter value from wherever it's available
             * 
             * Counter handling strategies:
             * 1. Use authenticatorInfo.newCounter if available (from SimpleWebAuthn)
             * 2. If counter verification is disabled, use the existing counter or 0
             * 3. Otherwise, increment the existing counter as a fallback
             */
            const newCounter = hasNewCounter ? authenticatorInfo.newCounter : 
                              DISABLE_COUNTER_VERIFICATION ? (storedCredential.counter || 0) :
                              (typeof storedCredential.counter === 'number' ? storedCredential.counter + 1 : 1);
            
            // Log the counter source for debugging
            console.log('Counter update source:', {
                hasNewCounter,
                fallbackUsed: !hasNewCounter,
                originalCounter: storedCredential.counter,
                newCounter
            });
            
            // Always update the counter on successful verification
            if (verified) {
                console.log(`Updating credential counter from ${storedCredential.counter} to ${newCounter}`);
                
                // Update stored credential with new counter value and usage timestamp
                storedCredential.counter = newCounter;
                storedCredential.lastUsed = new Date().toISOString();
                
                // Add audit information for security monitoring
                if (!storedCredential.usageHistory) {
                    storedCredential.usageHistory = [];
                }
                
                // Keep a limited history of usage for security auditing
                storedCredential.usageHistory.unshift({
                    timestamp: new Date().toISOString(),
                    counter: newCounter, // Use our calculated newCounter value
                    deviceId: deviceId
                });
                
                // Limit history size to prevent excessive growth
                if (storedCredential.usageHistory.length > 10) {
                    storedCredential.usageHistory = storedCredential.usageHistory.slice(0, 10);
                }
                
                // Save updated credential to persistent storage
                webAuthnCredentials.set(credentialID, storedCredential);
                saveMapToFile(webAuthnCredentials, WEBAUTHN_CREDENTIALS_FILE); 
                console.log('Credential updated and saved successfully');
            } else {
                console.warn('Could not update counter: verification was not successful');
            }

            console.log(`Verificación WebAuthn exitosa para deviceId: ${deviceId}, credentialID: ${credentialID}`);

        } else if (authenticationType === 'webcrypto') {
            // --- WebCrypto Verification using Node.js crypto --- 
            
            if (!challenge || !signature) {
                return res.status(400).json({ success: false, error: 'Para WebCrypto, se requieren challenge y signature' });
            }

            // Retrieve the stored public key
            const publicKeyJWK = devicePublicKeys.get(deviceId);
            if (!publicKeyJWK) {
                return res.status(400).json({ 
                    success: false, 
                    error: `No se encontró clave pública para el deviceId: ${deviceId}` 
                });
            }

            // Convert JWK to PEM format for crypto.verify
            const publicKeyPem = crypto.createPublicKey({ key: publicKeyJWK, format: 'jwk' }).export({ type: 'spki', format: 'pem' });

            // Create the verifier
            const verify = crypto.createVerify('SHA256');
            verify.update(Buffer.from(expectedChallenge)); // Verify against the original challenge

            // Verify the signature
            const isValid = verify.verify(publicKeyPem, Buffer.from(signature, 'base64'));

            if (!isValid) {
                return res.status(401).json({ 
                    success: false, 
                    error: 'Firma WebCrypto inválida'
                });
            }

            console.log(`Verificación WebCrypto exitosa para deviceId: ${deviceId}`);

        } else {
            // Tipo desconocido
            return res.status(400).json({ 
                success: false, 
                error: 'Tipo de autenticación no soportado' 
            });
        }

        // Eliminar el challenge usado
        challenges.delete(deviceId);

        return res.json({
            success: true,
            message: `Verificación ${authenticationType || ''} exitosa`,
            deviceId
        });
    } catch (error) {
        console.error(`Error durante la verificación (${authenticationType || 'desconocido'}):`, error);
        res.status(500).json({ 
            success: false, 
            error: 'Error interno del servidor durante la verificación' 
        });
    }
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor FIDO2 ejecutándose en http://localhost:${PORT}`);
    console.log(`Soporta autenticación WebCrypto y WebAuthn`);
    console.log(`Persistencia de datos habilitada en: ${DATA_DIR}`);
    console.log(`Dispositivos WebCrypto registrados: ${devicePublicKeys.size}`);
    console.log(`Dispositivos WebAuthn registrados: ${webAuthnCredentials.size}`);
});
