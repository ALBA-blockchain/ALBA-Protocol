const { expect } = require("chai");
const testdata = require("../data/jsonTestData.json");
const { ethers } = require("hardhat");
const EthCrypto = require('eth-crypto');

describe("ParseBitcoinRawTx", function() {
    let PaContractFactory;
    let ParseBitcoinRawTx;

    beforeEach(async () => {
        ParseBitcoinRawTxContractFactory = await ethers.getContractFactory("ParseBitcoinRawTx");
        ParseBitcoinRawTx = await ParseBitcoinRawTxContractFactory.deploy();
        await ParseBitcoinRawTx.deployed();

    });

    describe("Test ParseBitcoinRawTx", function () {

        it("Verify function getOutputsData correctly extracts output data from P's unlocked commitment transaction", async function () {
            const returnedValues = await ParseBitcoinRawTx.getOutputsDataLNB(testdata.new_CT_P_unlocked);
            const htlc = returnedValues[0];
            const p2pkh = returnedValues[1];
            const opreturn = returnedValues[2];
            expect(htlc.value).to.equal(18085); 
            expect(htlc.pk1).to.equal("0x13f17fa639f9cf2108e9dc9a14df8a9d5b9f1df1a91efe3d2830e08edd71e182");
            expect(htlc.rev_secret).to.equal("0x6016ad000e6033da466b4a085361bdb66bd6ce199198f1f4b46bf5317e86f95c"); 
            expect(htlc.pk2).to.equal("0x40602913fbabf074554d1db1c9a108978167734826e36bddfb8830852de2137f"); 
            expect(p2pkh.value).to.equal(18085);
            expect(p2pkh.pkhash).to.equal("0xc0d90b19a448b569bd0cc77b3da2dd5bb41d2c9f"); 
            expect(opreturn.value).to.equal(0); 
            expect(opreturn.data).to.equal("0xf0f0427c47433d9d440fc105e7d61d1520b5c889ac6405596362fdce95658a35"); 
        })

        it("Verify function getOutputsData correctly extracts output data from V's unlocked commitment transaction", async function () {
            const returnedValues = await ParseBitcoinRawTx.getOutputsDataLN(testdata.new_CT_V_unlocked);
            const htlc = returnedValues[0];
            const p2pkh = returnedValues[1];
            const opreturn = returnedValues[2];
            expect(htlc.value).to.equal(8790); 
            expect(htlc.pk1).to.equal("0x40602913fbabf074554d1db1c9a108978167734826e36bddfb8830852de2137f");
            expect(htlc.rev_secret).to.equal("0x1129672217863dba8accf8bd40cfa6d9728e4ea71a1ce98b3cdac50e8bac8c64"); 
            expect(htlc.pk2).to.equal("0x13f17fa639f9cf2108e9dc9a14df8a9d5b9f1df1a91efe3d2830e08edd71e182"); 
            expect(p2pkh.value).to.equal(8790);
            expect(p2pkh.pkhash).to.equal("0x172b8ab555aa28d6bd281de387d3ec9bd47e22ab"); 
        })

        it("Revert if Commitment Tx has more than one input", async function () {
             await expect(ParseBitcoinRawTx.getInputsData(testdata.rawFundingTransaction)).to.be.revertedWith("Tx has too many inputs (>1)");
        })

        it("Verify function getInputsData correctly extracts number of inputs, txid, and index", async function () {
            const returnedValues = await ParseBitcoinRawTx.getInputsData(testdata.new_CT_P_locked);
            expect(returnedValues.number_of_inputs).to.equal(1); // number of inputs
            expect(returnedValues.txid).to.equal("0xf6617e14ee663db4eed1cc0367c2d770e4eb95e56b97d7785b13e5b57dcf9674"); // txid
            expect(returnedValues.inputIndex).to.equal("0x00000000"); // index of the input (4 bytes)
        })

        it("Verify timelock is correctly extracted: there is timelock ", async function () {
            const timelock = await ParseBitcoinRawTx.getTimelock(testdata.new_CT_P_locked);
            expect(timelock).to.equal("0x16997891");
        }) 

        it("Verify timelock is correctly extracted: no timelock", async function () {
            const timelock = await ParseBitcoinRawTx.getTimelock(testdata.new_CT_P_unlocked);
            expect(timelock).to.equal("0x00000000"); 
        }) 

        /*
        it("Verify Ethereum signature", async function () {
            const identity = EthCrypto.createIdentity(); //create identity
            const publicKey = EthCrypto.publicKeyByPrivateKey(identity.privateKey);
            const address = EthCrypto.publicKey.toAddress(publicKey);
            const digest = "0xfb4e6075077d50e3487a303ddaeadf7eb43d9c6e93c2d9d5325c2c77dd94c550";
            const signature = EthCrypto.sign(identity.privateKey, digest);

            const returnedValue = await ParseBitcoinRawTx.verifyETHSignature(digest, signature);
            expect(address).to.equal(returnedValue);
        })
        */

        it("Verify Bitcoin signature P", async function () {
            // Ethereum uses keccak256 for signing, and bitcoin libraries normally use sha256, so you have to use ethereum libraries for signing. I worked from the wrong assumption that I could use existing Bitcoin tools for signing the message and then recover it on the Ethereum side (https://ethereum.stackexchange.com/questions/32401/verifying-bicoin-signed-message-in-ethereum-smart-contract)

            const returnedValue = await ParseBitcoinRawTx.verifyBTCSignature(testdata.TxPDigest, testdata.V, testdata.R, testdata.S);
            expect(testdata.pkProverUnprefixedUncompressed).to.equal(returnedValue);

        })

        it("Verify Bitcoin signature V", async function () {
            // Ethereum uses keccak256 for signing, and bitcoin libraries normally use sha256, so you have to use ethereum libraries for signing. I worked from the wrong assumption that I could use existing Bitcoin tools for signing the message and then recover it on the Ethereum side (https://ethereum.stackexchange.com/questions/32401/verifying-bicoin-signed-message-in-ethereum-smart-contract)

            const returnedValue = await ParseBitcoinRawTx.verifyBTCSignature(testdata.TxPDigest, testdata.V, testdata.R_V, testdata.S_V);
            expect(testdata.pkVerifierUnprefixedUncompressed).to.equal(returnedValue);

        })

        it("Extract signatures from raw transaction", async function () {

            const sigs = await ParseBitcoinRawTx.getSignatures(testdata.TxSigned);
            expect(sigs[0].r).to.equal(testdata.R);
            expect(sigs[0].s).to.equal(testdata.S);
            expect(sigs[1].r).to.equal(testdata.R_V);
            expect(sigs[1].s).to.equal(testdata.S_V);

        })

        it("Extract tx digest from P's raw transaction", async function () {

            const digest = await ParseBitcoinRawTx.getTxDigest(testdata.CT_P_withVsig_Unlocked, testdata.fundingTx_LockingScript, testdata.sighash_all);
            expect(digest).to.equal("0x8b2bb9663013661e4405e37374ed3c6f9c50dea2c0a31f6a475e8f78c5964a6e"); // new digest

        })

        it("Extract tx digest from V's raw transaction", async function () {

            const digest = await ParseBitcoinRawTx.getTxDigest(testdata.CT_V_withPsig_Unlocked, testdata.fundingTx_LockingScript, testdata.sighash_all);
            expect(digest).to.equal(testdata.TxVDigest);

        })

        it("Extract pk keys from funding transaction script", async function () {

            const pks = await ParseBitcoinRawTx.extractCompressedPK(testdata.fundingTx_LockingScript);
            expect(pks[0]).to.equal(testdata.pkProver);
            expect(pks[1]).to.equal(testdata.pkVerifier);

        })
        

    });

})