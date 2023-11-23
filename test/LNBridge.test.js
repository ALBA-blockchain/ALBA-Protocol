const { expect } = require("chai");
//const SHA256 = require('crypto-js/sha256')
const testdata = require("../data/jsonTestData.json");
const { ethers } = require("hardhat");
const EthCrypto = require('eth-crypto');
const { sha256 } = require("ethers/lib/utils");

describe("ALBA", function(account) {
    let ALBAContractFactory;
    let ALBA;

    beforeEach(async () => {

        // create identities for Prover and Verifier
        // const [prover, verifier] = await ethers.getSigners(); // returns an array of addresses, I keep only the first two

        //const proverBalance = await ethers.provider.getBalance(prover.address); // 10000000000000000000000
        //const verifierBalance = await ethers.provider.getBalance(verifier.address); // 10000000000000000000000

        //create identity P
        const entropyP = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociao', 'utf-8');
        const identityP = EthCrypto.createIdentity(entropyP); //create identity
        //console.log(identityP);
        const publicKeyP = EthCrypto.publicKeyByPrivateKey(identityP.privateKey);
        const addressP = EthCrypto.publicKey.toAddress(publicKeyP);
        //create identity V
        const entropyV = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaohallo', 'utf-8');
        const identityV = EthCrypto.createIdentity(entropyV); //create identity
        const publicKeyV = EthCrypto.publicKeyByPrivateKey(identityV.privateKey);
        const addressV = EthCrypto.publicKey.toAddress(publicKeyV); 


        ALBAContractFactory = await ethers.getContractFactory("ALBA");
        ALBA = await ALBAContractFactory.deploy(addressP, addressV);
        await ALBA.deployed();

        const [prover, verifier] = await ethers.getSigners();

        // Prover locks coins
        await prover.sendTransaction({
            to: ALBA.address,
            value: ethers.utils.parseEther("0.5"), // Sends 0.5 ether
        });

        // Verifier locks coins
        await verifier.sendTransaction({
            to: ALBA.address,
            value: ethers.utils.parseEther("0.5"), // Sends 0.5 ether
        });

    });

    /* describe("Test Signature with ecrecovery", function () {

        it("Call checkSignatureNew, sig of P over CTV", async function () {

            let tx = await ALBA.checkSignatureEcrecover(testdata.CT_V_withPsig_Unlocked, testdata.fundingTx_LockingScript, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed);
        }) 

        it("Call checkSignatureNew, sig of V over CTP", async function () {

            let tx = await ALBA.checkSignatureEcrecover(testdata.CT_P_withVsig_Unlocked, testdata.fundingTx_LockingScript, testdata.sighash_all, testdata.pkVerifierUnprefixedUncompressed);
        }) 
    }); */

    describe("Test Setup", function () {

        it("Populate Setup", async function () {

            //recall identity P
            const entropyP = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociao', 'utf-8');
            const identityP = EthCrypto.createIdentity(entropyP); //create identity
            const publicKeyP = EthCrypto.publicKeyByPrivateKey(identityP.privateKey);
            const addressP = EthCrypto.publicKey.toAddress(publicKeyP);
            //recall identity V
            const entropyV = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaohallo', 'utf-8');
            const identityV = EthCrypto.createIdentity(entropyV); //create identity
            const publicKeyV = EthCrypto.publicKeyByPrivateKey(identityV.privateKey);
            const addressV = EthCrypto.publicKey.toAddress(publicKeyV); 

            const digest = testdata.setupMessageDigest;
            const signatureP = EthCrypto.sign(identityP.privateKey, digest);
            const signatureV = EthCrypto.sign(identityV.privateKey, digest);

            let tx = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, signatureP, signatureV);
            const receipt = await ethers.provider.getTransactionReceipt(tx.hash);
        }) 

        
        it("Revert if signature of P over setup data is invalid", async function () {

            await expect(ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigPWrong, testdata.setupSigV)).to.be.revertedWith("Invalid signatures over setup data");

        }) 

        it("Revert if signature of V over setup data is invalid", async function () {

            await expect(ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigVWrong)).to.be.revertedWith("Invalid signatures over setup data");

        })  
        
    });  

    describe("Test Receive", async () => {

        it("Should emit event lockCoinsEvent(address addr, uint amount) when coins are successfully deposited", async function () {

            const [prover, verifier] = await ethers.getSigners();

            const initialBalance = await ethers.provider.getBalance(ALBA.address)

            // Send Ether to the contract using a simple Ether transfer
            const amountToSend = ethers.utils.parseEther("0.1")
            await prover.sendTransaction({ to: ALBA.address, value: amountToSend })
            await verifier.sendTransaction({ to: ALBA.address, value: amountToSend })

            // Check if the contract's balance increased by the sent amount
            const finalBalance = await ethers.provider.getBalance(ALBA.address)
            const totalAmountSent = ethers.utils.parseEther("0.2")
            expect(finalBalance).to.equal(initialBalance.add(totalAmountSent))

            // Check if the Log event was emitted with the correct data
            const logs = await ALBA.queryFilter("lockEvent")
            expect(logs.length).to.equal(4)
            // I pick the third event, as the first two are emitted in the BeforeEach at the beginning
            const logP = logs[2]
            expect(logP.args.label).to.equal("Coins locked!")
            expect(logP.args.addr).to.equal(prover.address)
            expect(logP.args.amount).to.equal(ethers.utils.parseEther("0.1"))
            // I pick the fourth event
            const logV = logs[3]
            expect(logV.args.label).to.equal("Coins locked!")
            expect(logV.args.addr).to.equal(verifier.address)
            expect(logV.args.amount).to.equal(ethers.utils.parseEther("0.1"))

        })

        /* it("Should emit event Failed to lock coins: msg.sender is not P nor V", async function () {

            const [prover, verifier, other] = await ethers.getSigners();

            const amountToSend = ethers.utils.parseEther("0.1")
            await other.sendTransaction({ to: ALBA.address, value: amountToSend })

            // Check if the Log event was emitted with the correct data
            const logs = await ALBA.queryFilter("stateEvent")
            expect(logs.length).to.equal(1)
            // I pick the third event, as the first two are emitted in the BeforeEach at the beginning
            const logP = logs[0]
            expect(logP.args.label).to.equal("Failed to lock coins: msg.sender is not P nor V")
            expect(logP.args.stateStatus).to.equal(false)
        }) */
    }); 
 
 
    describe("Test optimisticSubmitProof", function () {

        it("Optimistic submitProof ", async function () {

            //recall identity P
            const entropyP = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociao', 'utf-8');
            const identityP = EthCrypto.createIdentity(entropyP); //create identity
            const publicKeyP = EthCrypto.publicKeyByPrivateKey(identityP.privateKey);
            const addressP = EthCrypto.publicKey.toAddress(publicKeyP);
            //recall identity V
            const entropyV = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaohallo', 'utf-8');
            const identityV = EthCrypto.createIdentity(entropyV); //create identity
            const publicKeyV = EthCrypto.publicKeyByPrivateKey(identityV.privateKey);
            const addressV = EthCrypto.publicKey.toAddress(publicKeyV); 

            const digest = testdata.optimisticProofMessageDigest;
            const signatureP = EthCrypto.sign(identityP.privateKey, digest);
            const signatureV = EthCrypto.sign(identityV.privateKey, digest);
            //console.log("sig P");
            //console.log(signatureP);
            //console.log("sig V");
            //console.log(signatureV); 
 
            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txoptimisticSubmitProof = await ALBA.optimisticSubmitProof(signatureP, signatureV, 12);

        }) 

        it("Emit event that proof has been verified ", async function () {

            //recall identity P
            const entropyP = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociao', 'utf-8');
            const identityP = EthCrypto.createIdentity(entropyP); //create identity
            const publicKeyP = EthCrypto.publicKeyByPrivateKey(identityP.privateKey);
            const addressP = EthCrypto.publicKey.toAddress(publicKeyP);
            //recall identity V
            const entropyV = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaohallo', 'utf-8');
            const identityV = EthCrypto.createIdentity(entropyV); //create identity
            const publicKeyV = EthCrypto.publicKeyByPrivateKey(identityV.privateKey);
            const addressV = EthCrypto.publicKey.toAddress(publicKeyV); 

            const digest = testdata.optimisticProofMessageDigest;
            const signatureP = EthCrypto.sign(identityP.privateKey, digest);
            const signatureV = EthCrypto.sign(identityV.privateKey, digest);
 
            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            //let txoptimisticSubmitProof = await ALBA.optProof(signatureP, signatureV, 12);
            await expect(ALBA.optimisticSubmitProof(signatureP, signatureV, 12)).to.emit(ALBA, "stateEvent").withArgs("Proof optimistically verified", true);

        }) 

        it("Emit event that proof failed to verify ", async function () {

            //recall identity P
            const entropyP = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociao', 'utf-8');
            const identityP = EthCrypto.createIdentity(entropyP); //create identity
            const publicKeyP = EthCrypto.publicKeyByPrivateKey(identityP.privateKey);
            const addressP = EthCrypto.publicKey.toAddress(publicKeyP);
            //recall identity V
            const entropyV = Buffer.from('ciaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaociaohallo', 'utf-8');
            const identityV = EthCrypto.createIdentity(entropyV); //create identity
            const publicKeyV = EthCrypto.publicKeyByPrivateKey(identityV.privateKey);
            const addressV = EthCrypto.publicKey.toAddress(publicKeyV); 

            const digest = testdata.optimisticProofMessageDigest;
            const wrongDigest = testdata.optimisticProofMessageDigestW;
            const signatureP = EthCrypto.sign(identityP.privateKey, digest);
            const signatureV = EthCrypto.sign(identityV.privateKey, wrongDigest);
 
            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            //let txoptimisticSubmitProof = await ALBA.optProof(signatureP, signatureV, 12);
            await expect(ALBA.optimisticSubmitProof(signatureP, signatureV, 12)).to.emit(ALBA, "stateEvent").withArgs("Proof verification failed", false);


        }) 
    }); 

    describe("Test SubmitProof", function () {

        it("Is Proof valid?", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txSubmitProof = await ALBA.submitProof(testdata.CT_P_withVsig_Unlocked, testdata.CT_V_withPsig_Unlocked);

        }) 

        it("Revert if current time is smaller than the time in the timelock. Event: Proof successfully verified", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_Unlocked, testdata.CT_V_withPsig_Unlocked)).to.emit(ALBA, "stateEvent").withArgs("Proof successfully verified", true);
        }) 

        it("Revert if current time is smaller than the time in the timelock. Event: Proof verification failed", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.smallTimelock, testdata.RelTimelock, testdata.setupSigPSmallTimelock, testdata.setupSigVSmallTimelock);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_Unlocked, testdata.CT_V_withPsig_Unlocked)).to.emit(ALBA, "stateEvent").withArgs("Proof verification failed", false);
        })

        it("Revert if P's transaction is locked", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked)).to.be.revertedWith("CTxP locked");
        })
        
        it("Revert if V's transaction is locked", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_Unlocked, testdata.CT_V_withPsig_Locked)).to.be.revertedWith("CTxV locked");
        })

        it("Revert if P's commitment transaction does not hardcode V's revocation key", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_Unlocked_WrongRevSecret, testdata.CT_V_withPsig_Unlocked)).to.be.revertedWith("P's commitment transaction does not hardcode V's revocation key");
        })

        it("Revert if there is an mismatch between the amounts in p2pkh of P and in lightning HTLC of V (wrong P2PKH of P)", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_Unlocked_WrongAmountP2PKH, testdata.CT_V_withPsig_Unlocked)).to.be.revertedWith("Amount mismatch between p2pkh of P and lightning HTLC of V");

        }) 

        it("Revert if there is an mismatch between the amounts in p2pkh of P and in lightning HTLC of V (wrong HTLC of V)", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_Unlocked, testdata.CT_V_withPsig_Unlocked_WrongAmountHTLC)).to.be.revertedWith("Amount mismatch between p2pkh of P and lightning HTLC of V");

        }) 

        it("Revert if there is an mismatch between the amounts in p2pkh of P and in lightning HTLC of V", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_Unlocked_WrongAmountHTLC, testdata.CT_V_withPsig_Unlocked_WrongAmountP2PKH)).to.be.revertedWith("Amount mismatch between p2pkh of V and lightning HTLC of P");

        }) 

        it("Revert if the p2pkh in P's unlocked commitment transaction does not correspond to Verifier's one", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_Unlocked_WrongP2pkh, testdata.CT_V_withPsig_Unlocked)).to.be.revertedWith("The p2pkh in P's unlocked commitment transaction does not correspond to Verifier's one");
        }) 

        it("Revert if the p2pkh in V's unlocked commitment transaction does not correspond to Prover's one", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_Unlocked, testdata.CT_V_withPsig_Unlocked_WrongP2pkh)).to.be.revertedWith("The p2pkh in V's unlocked commitment transaction does not correspond to Prover's one");
        }) 

        it("Revert if P's commitment transaction does not spend the funding transaction", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_WrongFund, testdata.CT_V_withPsig_Unlocked)).to.be.revertedWith("CTxP does not spend funding Tx");
        })

        it("Revert if V's commitment transaction does not spend the funding transaction", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_Unlocked, testdata.CT_V_withPsig_WrongFund)).to.be.revertedWith("CTxV does not spend funding Tx");
        })

        it("Revert if verification of signature of P failed", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withVsig_Unlocked, testdata.CT_V_withWrongPsig_Unlocked)).to.be.revertedWith("Invalid signature of P over CTxV");

        }) 

        it("Revert if verification of signature of V failed", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.submitProof(testdata.CT_P_withWrongVsig_Unlocked, testdata.CT_V_withPsig_Unlocked)).to.be.revertedWith("Invalid signature of V over CTxP");

        })  

    }); 

    describe("Test Dispute", function () {

        it("Call Dispute", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let tx = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);
        }) 

        it("Revert if current time is smaller than the time in the timelock. Event: Dispute successfully opened", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked)).to.emit(ALBA, "stateEvent").withArgs("Dispute opened", true);
        }) 

        it("Revert if current time is smaller than the time in the timelock. Event: Dispute not opened", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.smallTimelock, testdata.RelTimelock, testdata.setupSigPSmallTimelock, testdata.setupSigVSmallTimelock);

            await expect(ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked)).to.emit(ALBA, "stateEvent").withArgs("Failed to open dispute", false);
        })

        it("Check timelocked TxCP has timelock larger than Timelock T + Relative Timelock T_rel (false)", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.dispute(testdata.CT_P_withVsig_LockedOct29, testdata.CT_V_withPsig_Unlocked)).to.be.revertedWith("CTxP is unlocked or its timelocked is smaller than/equal to T + T_rel"); // tests with timelock run in October/Novemeber 2023. Testdata with timelock must be changed is tests are run later on. 
        }) 
        
        it("Check timelocked TxCP has timelock larger than Timelock T + Relative Timelock T_rel (true)", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let tx = await ALBA.dispute(testdata.CT_P_withVsig_LockedDec24, testdata.CT_V_withPsig_Unlocked);
        }) 

        it("Revert if verification of signature of P failed", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withWrongPsig_Unlocked)).to.be.revertedWith("Invalid signature of P over CTxV");

        }) 

        it("Revert if verification of signature of V failed", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            await expect(ALBA.dispute(testdata.CT_P_withWrongVsig_Locked, testdata.CT_V_withPsig_Unlocked)).to.be.revertedWith("Invalid signature of V over CTxP");
        }) 

    }); 

    describe("Test ResolveValidDispute", function () {

        it("Call resolveValidDispute", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txDispute = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            let tx = await ALBA.resolveValidDispute(testdata.CT_P_withVsig_Unlocked);
        }) 

        it("Emit event: Resolve Valid Dispute successfully executed", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txDispute = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            await expect(ALBA.resolveValidDispute(testdata.CT_P_withVsig_Unlocked)).to.emit(ALBA, "stateEvent").withArgs("Valid Dispute resolved", true);
        }) 

        it("Emit event: Resolve Valid Dispute failed", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            //let txDispute = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            await expect(ALBA.resolveValidDispute(testdata.CT_P_withVsig_Unlocked)).to.emit(ALBA, "stateEvent").withArgs("Valid Dispute unresolved", false);
        }) 

        it("Revert if transaction submitted is locked", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txDispute = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            await expect(ALBA.resolveValidDispute(testdata.CT_P_withVsig_Locked)).to.be.revertedWith("CTxP locked");
        })

        it("Revert if verification of signature of V failed", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txDispute = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            await expect(ALBA.resolveValidDispute(testdata.CT_P_withWrongVsig_Unlocked)).to.be.revertedWith("Invalid signature");
        })


    });

    describe("Test ResolveInvalidDispute", function () {

        it("Call resolveInvalidDispute", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txDispute = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            let tx = await ALBA.resolveInvalidDispute(testdata.revSecretP);
        }) 

        it("Emit event: Resolve Invalid Dispute successfully executed", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txDispute = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            await expect(ALBA.resolveInvalidDispute(testdata.revSecretP)).to.emit(ALBA, "stateEvent").withArgs("Invalid Dispute resolved", true);
        }) 

        it("Emit event: Resolve Invalid Dispute failed", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txDispute = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            await expect(ALBA.resolveInvalidDispute(testdata.WrongRevSecretP)).to.emit(ALBA, "stateEvent").withArgs("Invalid Dispute unresolved", false);
        }) 

    }); 

    describe("Test Settle", function () {

        it("Call settle right after locking coins", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txDispute = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            let txResolveDispute = await ALBA.resolveInvalidDispute(testdata.revSecretP);

            let settle = await ALBA.settle();
        }) 

        it("Valid proof submitted and funds distributed", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txDispute = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            let txResolveDispute = await ALBA.resolveValidDispute(testdata.CT_P_withVsig_Unlocked);

            await expect(ALBA.settle()).to.emit(ALBA, "stateEvent").withArgs("Valid proof submitted and funds distributed", true);
        }) 

        it("Emit event: Contract instance closed: invalid dispute opened, all funds given to V", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txDispute = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            let txResolveDispute = await ALBA.resolveInvalidDispute(testdata.revSecretP);

            await expect(ALBA.settle()).to.emit(ALBA, "stateEvent").withArgs("All funds given to V", true);
        }) 

        it("Emit event: Contract instance closed: dispute was not closed, all funds given to P", async function () {

            let txSetup = await ALBA.setup(testdata.fundingTxId, testdata.fundingTx_LockingScript, testdata.fundingTxIndex, testdata.sighash_all, testdata.pkProverUnprefixedUncompressed, testdata.pkVerifierUnprefixedUncompressed, testdata.timelock, testdata.RelTimelock, testdata.setupSigP, testdata.setupSigV);

            let txDispute = await ALBA.dispute(testdata.CT_P_withVsig_Locked, testdata.CT_V_withPsig_Unlocked);

            await expect(ALBA.settle()).to.emit(ALBA, "stateEvent").withArgs("All funds given to P", true);       
        }) 

        it("Emit event: Contract instance closed: Funds distributed as for initial distribution", async function () {

            await expect(ALBA.settle()).to.emit(ALBA, "stateEvent").withArgs("Funds distributed", true);       
        }) 

        // TODO: test balance distributions

    }); 
 
 
})