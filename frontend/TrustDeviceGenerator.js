// TrustDeviceGenerator.js
// Módulo para generar un DeviceID único utilizando TrustDevice-js

/**
 * Genera un DeviceID único utilizando TrustDevice-js
 * @returns {Promise<string>} Una promesa que se resuelve con el DeviceID
 */
export function generateDeviceId() {
    return new Promise((resolve, reject) => {
        try {
            // Configurar el callback para recibir el deviceId
            window._fmOpt = {
                success: function (result) {
                    if (result && result.device_id) {
                        resolve(result.device_id);
                    } else {
                        reject(new Error("No se pudo obtener el DeviceID"));
                    }
                },
                error: function (error) {
                    reject(error || new Error("Error al generar el DeviceID"));
                }
            };

            // Cargar el script de TrustDevice-js
            const script = document.createElement('script');
            script.type = 'text/javascript';
            script.async = true;
            // Usar la ruta absoluta para evitar problemas de carga
            script.src = './node_modules/@trustdevicejs/trustdevice-js/dist/fm.js?t=' + new Date().getTime();

            // Manejar errores de carga
            script.onerror = function () {
                reject(new Error("Error al cargar el script de TrustDevice-js"));
            };

            // Añadir el script al documento
            const firstScript = document.getElementsByTagName('script')[0];
            firstScript.parentNode.insertBefore(script, firstScript);
        } catch (error) {
            reject(error);
        }
    });
}
