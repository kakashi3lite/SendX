/**
 * Zero-Knowledge Cryptography Manager
 * Handles client-side encryption/decryption using WebCrypto API
 * All encryption happens in the browser - server never sees plaintext
 */

class CryptoManager {
    /**
     * Generate a new AES-GCM encryption key
     * @returns {Promise<CryptoKey>} Generated encryption key
     */
    static async generateKey() {
        try {
            return await crypto.subtle.generateKey(
                {
                    name: 'AES-GCM',
                    length: 256 // 256-bit key
                },
                true, // extractable
                ['encrypt', 'decrypt']
            );
        } catch (error) {
            console.error('Key generation failed:', error);
            throw new Error('Failed to generate encryption key');
        }
    }

    /**
     * Export key to base64 format for URL fragment
     * @param {CryptoKey} key - The key to export
     * @returns {Promise<string>} Base64 encoded key
     */
    static async exportKey(key) {
        try {
            const exported = await crypto.subtle.exportKey('raw', key);
            return this.arrayBufferToBase64(exported);
        } catch (error) {
            console.error('Key export failed:', error);
            throw new Error('Failed to export encryption key');
        }
    }

    /**
     * Import key from base64 format
     * @param {string} base64Key - Base64 encoded key
     * @returns {Promise<CryptoKey>} Imported key
     */
    static async importKey(base64Key) {
        try {
            const keyBuffer = this.base64ToArrayBuffer(base64Key);
            return await crypto.subtle.importKey(
                'raw',
                keyBuffer,
                { name: 'AES-GCM' },
                false, // not extractable
                ['decrypt']
            );
        } catch (error) {
            console.error('Key import failed:', error);
            throw new Error('Failed to import encryption key');
        }
    }

    /**
     * Encrypt plaintext using AES-GCM
     * @param {string} plaintext - Text to encrypt
     * @param {CryptoKey} key - Encryption key
     * @returns {Promise<string>} Base64 encoded encrypted data
     */
    static async encrypt(plaintext, key) {
        try {
            // Generate random IV (12 bytes for GCM)
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            // Convert plaintext to bytes
            const encoder = new TextEncoder();
            const data = encoder.encode(plaintext);

            // Encrypt the data
            const encrypted = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128 // 128-bit authentication tag
                },
                key,
                data
            );

            // Combine IV and encrypted data
            const combined = new Uint8Array(iv.length + encrypted.byteLength);
            combined.set(iv);
            combined.set(new Uint8Array(encrypted), iv.length);

            // Return base64 encoded result
            return this.arrayBufferToBase64(combined.buffer);
        } catch (error) {
            console.error('Encryption failed:', error);
            throw new Error('Failed to encrypt data');
        }
    }

    /**
     * Decrypt ciphertext using AES-GCM
     * @param {string} base64Ciphertext - Base64 encoded encrypted data
     * @param {string|CryptoKey} keyOrBase64 - Decryption key or base64 key
     * @returns {Promise<string>} Decrypted plaintext
     */
    static async decrypt(base64Ciphertext, keyOrBase64) {
        try {
            // Import key if it's a string
            let key;
            if (typeof keyOrBase64 === 'string') {
                key = await this.importKey(keyOrBase64);
            } else {
                key = keyOrBase64;
            }

            // Decode the base64 data
            const combined = this.base64ToArrayBuffer(base64Ciphertext);
            const combinedBytes = new Uint8Array(combined);

            // Extract IV (first 12 bytes) and ciphertext
            const iv = combinedBytes.slice(0, 12);
            const ciphertext = combinedBytes.slice(12);

            // Decrypt the data
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                key,
                ciphertext
            );

            // Convert bytes back to text
            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        } catch (error) {
            console.error('Decryption failed:', error);
            throw new Error('Failed to decrypt data - invalid key or corrupted data');
        }
    }

    /**
     * Convert ArrayBuffer to base64 string
     * @param {ArrayBuffer} buffer - Buffer to convert
     * @returns {string} Base64 string
     */
    static arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Convert base64 string to ArrayBuffer
     * @param {string} base64 - Base64 string
     * @returns {ArrayBuffer} Array buffer
     */
    static base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Generate a secure random password
     * @param {number} length - Password length
     * @returns {string} Random password
     */
    static generateSecurePassword(length = 16) {
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        
        let password = '';
        for (let i = 0; i < length; i++) {
            password += charset[array[i] % charset.length];
        }
        return password;
    }

    /**
     * Validate that WebCrypto is available
     * @returns {boolean} True if WebCrypto is supported
     */
    static isSupported() {
        return typeof crypto !== 'undefined' && 
               typeof crypto.subtle !== 'undefined' &&
               typeof crypto.getRandomValues !== 'undefined';
    }

    /**
     * Securely clear sensitive data from memory
     * @param {string|ArrayBuffer} data - Data to clear
     */
    static clearSensitiveData(data) {
        if (typeof data === 'string') {
            // Can't actually clear strings in JS, but we can try
            data = null;
        } else if (data instanceof ArrayBuffer) {
            // Zero out the buffer
            const view = new Uint8Array(data);
            crypto.getRandomValues(view);
        }
    }

    /**
     * Generate a cryptographically secure URL-safe ID
     * @param {number} length - Length of the ID in bytes
     * @returns {string} URL-safe base64 ID
     */
    static generateSecureId(length = 16) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return this.arrayBufferToBase64(array.buffer)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }
}

// Validate WebCrypto support on load
if (!CryptoManager.isSupported()) {
    console.error('WebCrypto API is not supported in this browser');
    alert('Your browser does not support the required encryption features. Please use a modern browser with HTTPS.');
}

// Export for use in other scripts
window.CryptoManager = CryptoManager;
