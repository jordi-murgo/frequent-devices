/**
 * @abstract
 * Abstract base class defining the interface for Frequent Device clients (WebCrypto, WebAuthn).
 * Subclasses must implement all methods marked as abstract.
 */
export class FrequentDeviceClient {

    /**
     * @param {string} serverUrl - The base URL of the backend server.
     */
    constructor(serverUrl = '/api') {
        if (this.constructor === FrequentDeviceClient) {
            throw new Error("Abstract classes can't be instantiated.");
        }
        this.serverUrl = serverUrl;
        this.deviceId = null;
        this.publicKey = null;
        // Note: privateKey handling differs significantly, so it's managed within subclasses.
    }

    /**
     * Ensures a Device ID exists (loading from storage or generating a new one).
     * @abstract
     * @returns {Promise<string>} The Device ID.
     */
    async ensureDeviceId() {
        throw new Error("Method 'ensureDeviceId()' must be implemented.");
    }

    /**
     * Checks if a valid credential (keys, IDs) exists in local storage for the current deviceId.
     * Should also load relevant keys/IDs into the instance if found.
     * @abstract
     * @returns {Promise<boolean>} True if a credential exists, false otherwise.
     */
    async checkForExistingCredential() {
        throw new Error("Method 'checkForExistingCredential()' must be implemented.");
    }

    /**
     * Performs the device registration process with the backend server.
     * This involves sending the public key or credential information.
     * @abstract
     * @returns {Promise<object>} The server's response object (usually { success: boolean, ... }).
     */
    async registerDevice() {
        throw new Error("Method 'registerDevice()' must be implemented.");
    }

    /**
     * Performs the full authentication process (request challenge, sign, verify).
     * @abstract
     * @param {string|null} [customPassword=null] - Optional password for WebCrypto decryption.
     * @returns {Promise<object>} The server's verification result (usually { success: boolean, ... }).
     */
    async authenticate(customPassword = null) {
        throw new Error("Method 'authenticate()' must be implemented.");
    }

    /**
     * Validates if the current device appears to be registered (e.g., by attempting a challenge request).
     * Exact implementation might vary based on backend capabilities.
     * @abstract
     * @returns {Promise<boolean>} True if the device seems valid/registered.
     */
    async validateDevice() {
        throw new Error("Method 'validateDevice()' must be implemented.");
    }

    /**
     * Clears all locally stored credentials related to this client type.
     * @abstract
     */
    clearLocalCredentials() {
        throw new Error("Method 'clearLocalCredentials()' must be implemented.");
    }

    // --- Optional/Helper methods that might be common or specific ---
    // It might be beneficial to define interfaces for requestChallenge, signChallenge, verifySignature
    // if they are consistently used across different UI interactions, but for now,
    // let's keep the core interface focused on the main actions called from index.html.
}
