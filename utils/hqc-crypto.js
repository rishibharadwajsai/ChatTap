const crypto = require('crypto');

class HQCCrypto {
    constructor() {
        this.hashAlgorithm = 'sha3-512';
        this.saltLength = 32;
        this.ivLength = 16;
        this.keyLength = 64;
        this.iterations = 100000;
    }

    generateSalt() {
        return crypto.randomBytes(this.saltLength);
    }

    generateIV() {
        return crypto.randomBytes(this.ivLength);
    }

    generateSessionKey() {
        return crypto.randomBytes(this.keyLength);
    }

    deriveKey(password, salt) {
        return crypto.pbkdf2Sync(
            password, 
            salt, 
            this.iterations, 
            this.keyLength, 
            this.hashAlgorithm
        );
    }

    encrypt(data, key, iv) {
        const cipher = this._createCipher(key, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        return encrypted;
    }

    decrypt(encryptedData, key, iv) {
        const decipher = this._createDecipher(key, iv);
        const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
        return decrypted;
    }

    createHMAC(data, key) {
        const hmac = crypto.createHmac(this.hashAlgorithm, key);
        return hmac.update(data).digest();
    }

    verifyHMAC(data, key, receivedHmac) {
        try {
            const calculatedHmac = this.createHMAC(data, key);
            return crypto.timingSafeEqual(calculatedHmac, receivedHmac);
        } catch (e) {
            return false;
        }
    }

    _createCipher(key, iv) {
        const hash = crypto.createHash(this.hashAlgorithm);
        hash.update(key);
        hash.update(iv);
        const streamKey = hash.digest();
        
        let counter = 0;
        return {
            update: function(data) {
                const result = Buffer.alloc(data.length);
                for (let i = 0; i < data.length; i++) {
                    const keyByte = streamKey[(counter + i) % streamKey.length];
                    result[i] = data[i] ^ keyByte;
                }
                counter += data.length;
                return result;
            },
            final: function() {
                return Buffer.alloc(0);
            }
        };
    }

    _createDecipher(key, iv) {
        return this._createCipher(key, iv);
    }
}

module.exports = HQCCrypto;