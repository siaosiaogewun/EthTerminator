const {ethers} = require("ethers")


const wallet = ethers.Wallet.createRandom()
const words = wallet.mnemonic.phrase

console.log(ethers.utils.mnemonicToSeed(words))

let node = ethers.utils.HDNode.fromMnemonic(words)
let account1 = node.derivePath("m/44'/60'/0'/0/0")
let account2 = node.derivePath("m/44'/60'/0'/0/1")

console.log(`Address: ${account1.address}, Private Key: ${account1.privatekey}`)