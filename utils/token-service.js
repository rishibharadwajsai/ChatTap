const crypto = require('crypto');
const HQCCrypto = require('./hqc-crypto');
const hqc = new HQCCrypto();

const TOKEN_MASTER_KEY = process.env.TOKEN_MASTER_KEY || crypto.randomBytes(64).toString('hex');

class TokenService {
  constructor() {
    this.masterKey = Buffer.from(TOKEN_MASTER_KEY, 'hex');
  }

  generateToken(payload, expiresIn = 24 * 60 * 60 * 1000) { 
    const tokenData = {
      ...payload,
      exp: Date.now() + expiresIn
    };
    
    const data = JSON.stringify(tokenData);
    
    const iv = hqc.generateIV();
    
    const encrypted = hqc.encrypt(Buffer.from(data, 'utf8'), this.masterKey, iv);
    
    const hmac = hqc.createHMAC(encrypted, this.masterKey);
    
    const tokenParts = {
      iv: iv.toString('base64'),
      data: encrypted.toString('base64'),
      hmac: hmac.toString('base64')
    };
    
    return Buffer.from(JSON.stringify(tokenParts)).toString('base64');
  }

  verifyToken(token) {
    try {
      if (!token) {
        console.error('Token is null or undefined');
        return null;
      }
      
      console.log('Token format check:', token.substring(0, 20) + '...');
      
      const tokenParts = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
      const { iv, data, hmac } = tokenParts;
      
      if (!iv || !data || !hmac) {
        console.error('Token missing required parts');
        return null;
      }
      
      const ivBuffer = Buffer.from(iv, 'base64');
      const encryptedBuffer = Buffer.from(data, 'base64');
      const hmacBuffer = Buffer.from(hmac, 'base64');
      
      if (!hqc.verifyHMAC(encryptedBuffer, this.masterKey, hmacBuffer)) {
        console.error('HMAC verification failed');
        return null;
      }
      
      const decrypted = hqc.decrypt(encryptedBuffer, this.masterKey, ivBuffer);
      
      const payload = JSON.parse(decrypted.toString('utf8'));
      
      if (payload.exp && payload.exp < Date.now()) {
        return { expired: true };
      }
      
      return payload;
    } catch (error) {
      console.error('Token verification error:', error);
      return null;
    }
  }
}

module.exports = new TokenService();