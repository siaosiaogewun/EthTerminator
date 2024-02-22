const crypto = require('crypto');

const encryptedData = {
    iv: '214cc6fcd28c9e29c0d9dd5d4120c8da',
    encryptedPrivateKey: '7e669eaad5e2a9d328c92981989cb52ebc3b716b6b9d45971e50b845ec13a5975dc75ac4cc21d3c5792914f3d13b9ff2c59465343d4690d8a1ac8f414d1675ab8aa9d8da890f71dcde8c3d2d4769b539'
};

const encryptionKeyBase64 = 'an4dlV9ju1ZM04R_o-2RDwl7fxX-nGZQRHYc5N5OchM=';
const encryptionKey = Buffer.from(encryptionKeyBase64, 'base64');

const algorithm = 'aes-256-cbc';

function decryptPrivateKey(encryptedData, key) {
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedData.encryptedPrivateKey, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}

const decryptedPrivateKey = decryptPrivateKey(encryptedData, encryptionKey);
console.log('Decrypted Private Key:', decryptedPrivateKey);

