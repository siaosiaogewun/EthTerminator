const { ethers }  = require('ethers');

const mnemonic = "diary steak forest resist pumpkin grass outer punch bone saddle method umbrella";
const hdNode = ethers.HDNodeWallet.fromPhrase(mnemonic);

console.log(hdNode);

const secondAccount = hdNode.derivePath(`44'/60'/0'/0/0`);
const thirdAccount = hdNode.derivePath(`44'/60'/0'/0/1`);

console.log(secondAccount.address);
console.log(thirdAccount.address);