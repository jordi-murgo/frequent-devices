/**
 * Servidor para validación FIDO2 de dispositivos frecuentes
 * Proporciona endpoints para solicitar challenge y verificar firmas
 */
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Almacenamiento temporal de desafíos (en producción debería ser una base de datos)
const challenges = new Map();
// Almacenamiento de claves públicas de dispositivos (en producción debería ser una base de datos)
const devicePublicKeys = new Map();

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
    const { deviceId, publicKey } = req.body;
    
    if (!deviceId || !publicKey) {
        return res.status(400).json({ 
            success: false, 
            error: 'Se requiere deviceId y publicKey' 
        });
    }
    
    // Almacenar la clave pública asociada al deviceId
    devicePublicKeys.set(deviceId, publicKey);
    
    console.log(`Dispositivo registrado: ${deviceId}`);
    console.log(`Clave pública: ${JSON.stringify(publicKey).substring(0, 50)}...`);
    
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
    const { deviceId, challenge, signature } = req.body;
    
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
    
    // Obtener la clave pública del dispositivo
    const publicKeyJwk = devicePublicKeys.get(deviceId);
    
    if (!publicKeyJwk) {
        return res.status(400).json({ 
            success: false, 
            error: 'Dispositivo no registrado' 
        });
    }
    
    try {
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
            
            console.log(`Firma verificada correctamente para el dispositivo ${deviceId}`);
            
            return res.json({
                success: true,
                message: 'Firma verificada correctamente',
                deviceId
            });
        } else {
            console.log(`Verificación de firma fallida para el dispositivo ${deviceId}`);
            
            return res.status(400).json({
                success: false,
                error: 'La firma no pudo ser verificada'
            });
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

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor FIDO2 ejecutándose en http://localhost:${PORT}`);
});
