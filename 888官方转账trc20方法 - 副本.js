const TronWeb = require('tronweb');

async function sendTransaction() {
    const tronWeb = new TronWeb({
        fullHost: "https://api.shasta.trongrid.io",
        privateKey: "2113f0f6d51ba8289a8996ad974967c6e21c5472dac3906bda63ff1173efa7d8",
    });

    const options = {
        feeLimit: 10000000,
        callValue: 0
    };

    try {
        const tx = await tronWeb.transactionBuilder.triggerSmartContract(
            "TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs", 'transfer(address,uint256)', options,
            [{
                type: 'address',
                value: "TL1R6YacZuY2dVqNyreWexzb77Ct2QCick"
            }, {
                type: 'uint256',
                value: 1
            }],
            tronWeb.address.toHex("TL9Eh1ccGNncUE2e7hUY4C58sGCUpJaYao")
        );

        const signedTx = await tronWeb.trx.sign(tx.transaction);
        const broadcastTx = await tronWeb.trx.sendRawTransaction(signedTx);

        console.log(signedTx);
        console.log(broadcastTx);
    } catch (error) {
        console.error(error);
    }
}

// 调用异步函数
sendTransaction();
