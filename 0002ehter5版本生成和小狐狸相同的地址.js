const { ethers }  = require('ethers');

const mnemonic = "diary steak forest resist pumpkin grass outer punch bone saddle method umbrella";
let node = ethers.utils.HDNode.fromMnemonic(mnemonic)

console.log(node);

const secondAccount = node.derivePath(`m/44'/60'/0'/0/0`);
const thirdAccount = node.derivePath(`m/44'/60'/0'/0/1`);

console.log(secondAccount.address);
console.log(thirdAccount.address);