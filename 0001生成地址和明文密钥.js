const { ethers } = require("ethers");
const fs = require('fs/promises');
const readline = require('readline');

const filePath = 'output.txt';
const addressFilePath = 'addresses.txt';

async function saveToUnencryptedFile(address, privateKey) {
    const dataString = `${address}\n${privateKey}\n`;

    await fs.appendFile(filePath, dataString);
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

    const numWallets = 100;
    const basePath = "44'/60'/0'/0";

    for (let i = 1; i <= numWallets; i++) {
        const hdNodeNew = hdNode.derivePath(`${basePath}/${i}`);
        const wallet = new ethers.Wallet(hdNodeNew.privateKey);
        const address = wallet.address;
        const privateKey = wallet.privateKey;

        console.log(` ${address}`);

        await saveToUnencryptedFile(address, privateKey);
    }
}

async function main() {
    await generateAndSaveWallets();
}

main();
