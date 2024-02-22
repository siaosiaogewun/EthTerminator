const { ethers } = require("ethers");
const fs = require('fs/promises');
const crypto = require('crypto');
const readline = require('readline');

const filePath = 'output.txt';
const addressFilePath = 'addresses.txt';
const encryptionKeyBase64 = 'an4dlV9ju1ZM04R_o-2RDwl7fxX-nGZQRHYc5N5OchM=';
const encryptionKey = Buffer.from(encryptionKeyBase64, 'base64');

async function saveToEncryptedFile(address, privateKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
    let encryptedPrivateKey = cipher.update(privateKey, 'utf-8', 'hex');
    encryptedPrivateKey += cipher.final('hex');

    const encryptedDataString = `${address}\n-${iv.toString('hex')}-${encryptedPrivateKey}\n`;

    await fs.appendFile(filePath, encryptedDataString);
    await fs.appendFile(addressFilePath, `${address}\n`);
}

async function generateAndSaveWallets() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    // 使用 await 关键字等待用户输入
    const mnemonic = await new Promise(resolve => {
        rl.question('Enter your mnemonic: ', answer => {
            resolve(answer);
            rl.close();
        });
    });

    const hdNode = ethers.HDNodeWallet.fromPhrase(mnemonic);

    const numWallets = 10000;
    const basePath = "44'/60'/0'/0";

    for (let i = 1; i <= numWallets; i++) {
        const hdNodeNew = hdNode.derivePath(`${basePath}/${i}`);
        const wallet = new ethers.Wallet(hdNodeNew.privateKey);
        const address = wallet.address;
        const privateKey = wallet.privateKey;

        console.log(` ${address}`);
      

        await saveToEncryptedFile(address, privateKey);
    }
}

async function main() {
    await generateAndSaveWallets();
}

main();
