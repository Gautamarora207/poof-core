/* global artifacts, web3, contract */
require("chai")
  .use(require("bn-chai")(web3.utils.BN))
  .use(require("chai-as-promised"))
  .should();
const fs = require("fs");

const { getEncryptionPublicKey } = require("eth-sig-util");
const { hexToBytes, toBN, toWei } = require("web3-utils");
const {
  packEncryptedMessage,
  unpackEncryptedMessage,
} = require("../src/utils");
const Account = require("../src/account");
const { takeSnapshot, revertSnapshot } = require("../lib/ganacheHelper");

const Hasher = artifacts.require("./Hasher.sol");
const Verifier = artifacts.require("./Verifier.sol");
const Tornado = artifacts.require("./ERC20Tornado.sol");
const FeeManager = artifacts.require("./FeeManager.sol");
const BadRecipient = artifacts.require("./BadRecipient.sol");
const Token = artifacts.require("./ERC20Mock.sol");

const websnarkUtils = require("websnark/src/utils");
const buildGroth16 = require("websnark/src/groth16");
const stringifyBigInts =
  require("websnark/tools/stringifybigint").stringifyBigInts;
const snarkjs = require("snarkjs");
const bigInt = snarkjs.bigInt;
const crypto = require("crypto");
const circomlib = require("circomlib");
const MerkleTree = require("../lib/MerkleTree");
const { randomBN } = require("../src/utils");

const rbigint = (nbytes) =>
  snarkjs.bigInt.leBuff2int(crypto.randomBytes(nbytes));
const pedersenHash = (data) =>
  circomlib.babyJub.unpackPoint(circomlib.pedersenHash.hash(data))[0];
const toFixedHex = (number, length = 32) =>
  "0x" +
  bigInt(number)
    .toString(16)
    .padStart(length * 2, "0");
const getRandomRecipient = () => rbigint(20);

function generateDeposit() {
  let deposit = {
    secret: randomBN(31),
    nullifier: randomBN(31),
  };
  const preimage = Buffer.concat([
    deposit.nullifier.toBuffer("le", 31),
    deposit.secret.toBuffer("le", 31),
  ]);
  deposit.commitment = pedersenHash(preimage);
  return deposit;
}

contract("ERC20Tornado", (accounts) => {
  let tornado;
  let feeManager;
  let token;
  let badRecipient;
  const sender = accounts[0];
  const operator = accounts[0];
  const levels = 20;
  let tokenDenomination = toWei("1"); // 1 ether
  let snapshotId;
  let prefix = "test";
  let tree;
  const celoAmount = toWei("0.1");
  const fee = bigInt(celoAmount).shr(1);
  const refund = celoAmount;
  let recipient = getRandomRecipient();
  const relayer = accounts[1];
  let groth16;
  let circuit;
  let proving_key;

  // Public / private key pair used for encrypting / decrypting the deposit note
  const privateKey = web3.eth.accounts.create().privateKey.slice(2);
  const publicKey = getEncryptionPublicKey(privateKey);

  before(async () => {
    tree = new MerkleTree(levels, null, prefix);
    token = await Token.new();
    feeManager = await FeeManager.new(sender);
    const hasher = await Hasher.new();
    const verifier = await Verifier.new();
    await Tornado.link(Hasher, hasher.address);
    tornado = await Tornado.new(
      verifier.address,
      feeManager.address,
      tokenDenomination,
      levels,
      sender,
      token.address
    );

    await token.mint(sender, tokenDenomination);
    badRecipient = await BadRecipient.new();
    snapshotId = await takeSnapshot();
    groth16 = await buildGroth16();
    circuit = require("../build/circuits/withdraw.json");
    proving_key = fs.readFileSync(
      "build/circuits/withdraw_proving_key.bin"
    ).buffer;
  });

  describe("#constructor", () => {
    it("should initialize", async () => {
      const tokenFromContract = await tornado.token();
      tokenFromContract.should.be.equal(token.address);
    });
  });

  describe("#deposit", () => {
    it("should work", async () => {
      const commitment = toFixedHex(43);
      await token.approve(tornado.address, tokenDenomination);

      let { logs } = await tornado.deposit(commitment, [], { from: sender });

      logs[0].event.should.be.equal("Deposit");
      logs[0].args.commitment.should.be.equal(commitment);
      logs[0].args.leafIndex.should.be.eq.BN(0);
    });

    it("should not allow to send ether on deposit", async () => {
      const commitment = toFixedHex(43);
      await token.approve(tornado.address, tokenDenomination);

      let error = await tornado.deposit(commitment, [], {
        from: sender,
        value: 1e6,
      }).should.be.rejected;
      error.reason.should.be.equal(
        "ETH value is supposed to be 0 for ERC20 instance"
      );
    });
  });

  describe("#withdraw", () => {
    it("should work", async () => {
      const deposit = generateDeposit();
      const account = new Account({
        amount: tokenDenomination,
        secret: deposit.secret,
        nullifier: deposit.nullifier,
      });
      const encryptedMessage = packEncryptedMessage(account.encrypt(publicKey));
      const user = accounts[4];
      await tree.insert(deposit.commitment);
      await token.mint(user, tokenDenomination);

      const balanceUserBefore = await token.balanceOf(user);
      await token.approve(tornado.address, tokenDenomination, { from: user });
      // Uncomment to measure gas usage
      // let gas = await tornado.deposit.estimateGas(toBN(deposit.commitment.toString()), { from: user, gasPrice: '0' })
      // console.log('deposit gas:', gas)
      const { logs: depositLogs } = await tornado.deposit(
        toFixedHex(deposit.commitment),
        hexToBytes(encryptedMessage),
        { from: user, gasPrice: "0" }
      );

      const encryptedNoteLog = depositLogs[depositLogs.length - 1];
      encryptedNoteLog.event.should.be.equal("EncryptedNote");
      encryptedNoteLog.args.sender.should.be.equal(accounts[4]);
      encryptedNoteLog.args.encryptedNote.should.be.equal(encryptedMessage);
      const unpackedMessage = unpackEncryptedMessage(encryptedMessage);
      const decryptedAccount = Account.decrypt(privateKey, unpackedMessage);

      const balanceUserAfter = await token.balanceOf(user);
      balanceUserAfter.should.be.eq.BN(
        toBN(balanceUserBefore).sub(toBN(tokenDenomination))
      );

      const { root, path_elements, path_index } = await tree.path(0);
      // Circuit input
      const input = stringifyBigInts({
        // public
        root,
        nullifierHash: pedersenHash(
          decryptedAccount.nullifier.toBuffer("le", 31)
        ),
        relayer,
        recipient,
        fee,
        refund,

        // private
        nullifier: decryptedAccount.nullifier,
        secret: decryptedAccount.secret,
        pathElements: path_elements,
        pathIndices: path_index,
      });

      const proofData = await websnarkUtils.genWitnessAndProve(
        groth16,
        input,
        circuit,
        proving_key
      );
      const { proof } = websnarkUtils.toSolidityInput(proofData);

      const balanceTornadoBefore = await token.balanceOf(tornado.address);
      const balanceRelayerBefore = await token.balanceOf(relayer);
      const balanceRecieverBefore = await token.balanceOf(
        toFixedHex(recipient, 20)
      );

      const ethBalanceOperatorBefore = await web3.eth.getBalance(operator);
      const ethBalanceRecieverBefore = await web3.eth.getBalance(
        toFixedHex(recipient, 20)
      );
      const ethBalanceRelayerBefore = await web3.eth.getBalance(relayer);
      let isSpent = await tornado.isSpent(toFixedHex(input.nullifierHash));
      isSpent.should.be.equal(false);
      // Uncomment to measure gas usage
      // gas = await tornado.withdraw.estimateGas(proof, publicSignals, { from: relayer, gasPrice: '0' })
      // console.log('withdraw gas:', gas)
      const args = [
        toFixedHex(input.root),
        toFixedHex(input.nullifierHash),
        toFixedHex(input.recipient, 20),
        toFixedHex(input.relayer, 20),
        toFixedHex(input.fee),
        toFixedHex(input.refund),
      ];
      const { logs } = await tornado.withdraw(proof, ...args, {
        value: refund,
        from: relayer,
        gasPrice: "0",
      });

      const balanceTornadoAfter = await token.balanceOf(tornado.address);
      const balanceRelayerAfter = await token.balanceOf(relayer);
      const ethBalanceOperatorAfter = await web3.eth.getBalance(operator);
      const balanceRecieverAfter = await token.balanceOf(
        toFixedHex(recipient, 20)
      );
      const ethBalanceRecieverAfter = await web3.eth.getBalance(
        toFixedHex(recipient, 20)
      );
      const ethBalanceRelayerAfter = await web3.eth.getBalance(relayer);
      const feeBN = toBN(fee.toString());
      balanceTornadoAfter.should.be.eq.BN(
        toBN(balanceTornadoBefore).sub(toBN(tokenDenomination))
      );
      balanceRelayerAfter.should.be.eq.BN(
        toBN(balanceRelayerBefore).add(feeBN)
      );
      balanceRecieverAfter.should.be.eq.BN(
        toBN(balanceRecieverBefore).add(toBN(tokenDenomination).sub(feeBN))
      );

      ethBalanceOperatorAfter.should.be.eq.BN(toBN(ethBalanceOperatorBefore));
      ethBalanceRecieverAfter.should.be.eq.BN(
        toBN(ethBalanceRecieverBefore).add(toBN(refund))
      );
      ethBalanceRelayerAfter.should.be.eq.BN(
        toBN(ethBalanceRelayerBefore).sub(toBN(refund))
      );

      logs[0].event.should.be.equal("Withdrawal");
      logs[0].args.nullifierHash.should.be.equal(
        toFixedHex(input.nullifierHash)
      );
      logs[0].args.relayer.should.be.eq.BN(relayer);
      logs[0].args.fee.should.be.eq.BN(feeBN);
      isSpent = await tornado.isSpent(toFixedHex(input.nullifierHash));
      isSpent.should.be.equal(true);
    });

    it("should give fees when feeTo is set", async () => {
      await feeManager.setFeeTo(accounts[5]);
      await feeManager.setProtocolFeeDivisor(200);
      const balanceFeeToBefore = await token.balanceOf(accounts[5]);

      const deposit = generateDeposit();
      const user = accounts[4];
      await tree.insert(deposit.commitment);
      await token.mint(user, tokenDenomination);

      const balanceUserBefore = await token.balanceOf(user);
      await token.approve(tornado.address, tokenDenomination, { from: user });
      // Uncomment to measure gas usage
      // let gas = await tornado.deposit.estimateGas(toBN(deposit.commitment.toString()), { from: user, gasPrice: '0' })
      // console.log('deposit gas:', gas)
      await tornado.deposit(toFixedHex(deposit.commitment), [], {
        from: user,
        gasPrice: "0",
      });

      const balanceUserAfter = await token.balanceOf(user);
      balanceUserAfter.should.be.eq.BN(
        toBN(balanceUserBefore).sub(toBN(tokenDenomination))
      );

      const { root, path_elements, path_index } = await tree.path(0);
      // Circuit input
      const input = stringifyBigInts({
        // public
        root,
        nullifierHash: pedersenHash(deposit.nullifier.toBuffer("le", 31)),
        relayer,
        recipient,
        fee,
        refund,

        // private
        nullifier: deposit.nullifier,
        secret: deposit.secret,
        pathElements: path_elements,
        pathIndices: path_index,
      });

      const proofData = await websnarkUtils.genWitnessAndProve(
        groth16,
        input,
        circuit,
        proving_key
      );
      const { proof } = websnarkUtils.toSolidityInput(proofData);

      const balanceTornadoBefore = await token.balanceOf(tornado.address);
      const balanceRelayerBefore = await token.balanceOf(relayer);
      const balanceRecieverBefore = await token.balanceOf(
        toFixedHex(recipient, 20)
      );

      const ethBalanceOperatorBefore = await web3.eth.getBalance(operator);
      const ethBalanceRecieverBefore = await web3.eth.getBalance(
        toFixedHex(recipient, 20)
      );
      const ethBalanceRelayerBefore = await web3.eth.getBalance(relayer);
      let isSpent = await tornado.isSpent(toFixedHex(input.nullifierHash));
      isSpent.should.be.equal(false);
      // Uncomment to measure gas usage
      // gas = await tornado.withdraw.estimateGas(proof, publicSignals, { from: relayer, gasPrice: '0' })
      // console.log('withdraw gas:', gas)
      const args = [
        toFixedHex(input.root),
        toFixedHex(input.nullifierHash),
        toFixedHex(input.recipient, 20),
        toFixedHex(input.relayer, 20),
        toFixedHex(input.fee),
        toFixedHex(input.refund),
      ];
      const { logs } = await tornado.withdraw(proof, ...args, {
        value: refund,
        from: relayer,
        gasPrice: "0",
      });

      const balanceTornadoAfter = await token.balanceOf(tornado.address);
      const balanceRelayerAfter = await token.balanceOf(relayer);
      const ethBalanceOperatorAfter = await web3.eth.getBalance(operator);
      const balanceRecieverAfter = await token.balanceOf(
        toFixedHex(recipient, 20)
      );
      const ethBalanceRecieverAfter = await web3.eth.getBalance(
        toFixedHex(recipient, 20)
      );
      const ethBalanceRelayerAfter = await web3.eth.getBalance(relayer);
      const balanceFeeToAfter = await token.balanceOf(accounts[5]);
      const feeBN = toBN(fee.toString());
      const feeToFee = toBN(tokenDenomination).div(toBN(200));
      balanceTornadoAfter.should.be.eq.BN(
        toBN(balanceTornadoBefore).sub(toBN(tokenDenomination))
      );
      balanceRelayerAfter.should.be.eq.BN(
        toBN(balanceRelayerBefore).add(feeBN)
      );
      balanceRecieverAfter.should.be.eq.BN(
        toBN(balanceRecieverBefore).add(
          toBN(tokenDenomination).sub(feeBN).sub(feeToFee)
        )
      );

      ethBalanceOperatorAfter.should.be.eq.BN(toBN(ethBalanceOperatorBefore));
      ethBalanceRecieverAfter.should.be.eq.BN(
        toBN(ethBalanceRecieverBefore).add(toBN(refund))
      );
      ethBalanceRelayerAfter.should.be.eq.BN(
        toBN(ethBalanceRelayerBefore).sub(toBN(refund))
      );

      balanceFeeToAfter.sub(balanceFeeToBefore).should.be.eq.BN(feeToFee);

      logs[0].event.should.be.equal("Withdrawal");
      logs[0].args.nullifierHash.should.be.equal(
        toFixedHex(input.nullifierHash)
      );
      logs[0].args.relayer.should.be.eq.BN(relayer);
      logs[0].args.fee.should.be.eq.BN(feeBN);
      isSpent = await tornado.isSpent(toFixedHex(input.nullifierHash));
      isSpent.should.be.equal(true);
    });

    it("should return refund to the relayer is case of fail", async () => {
      const deposit = generateDeposit();
      const user = accounts[4];
      recipient = bigInt(badRecipient.address);
      await tree.insert(deposit.commitment);
      await token.mint(user, tokenDenomination);

      const balanceUserBefore = await token.balanceOf(user);
      await token.approve(tornado.address, tokenDenomination, { from: user });
      await tornado.deposit(toFixedHex(deposit.commitment), [], {
        from: user,
        gasPrice: "0",
      });

      const balanceUserAfter = await token.balanceOf(user);
      balanceUserAfter.should.be.eq.BN(
        toBN(balanceUserBefore).sub(toBN(tokenDenomination))
      );

      const { root, path_elements, path_index } = await tree.path(0);
      // Circuit input
      const input = stringifyBigInts({
        // public
        root,
        nullifierHash: pedersenHash(deposit.nullifier.toBuffer("le", 31)),
        relayer,
        recipient,
        fee,
        refund,

        // private
        nullifier: deposit.nullifier,
        secret: deposit.secret,
        pathElements: path_elements,
        pathIndices: path_index,
      });

      const proofData = await websnarkUtils.genWitnessAndProve(
        groth16,
        input,
        circuit,
        proving_key
      );
      const { proof } = websnarkUtils.toSolidityInput(proofData);

      const balanceTornadoBefore = await token.balanceOf(tornado.address);
      const balanceRelayerBefore = await token.balanceOf(relayer);
      const balanceRecieverBefore = await token.balanceOf(
        toFixedHex(recipient, 20)
      );

      const ethBalanceOperatorBefore = await web3.eth.getBalance(operator);
      const ethBalanceRecieverBefore = await web3.eth.getBalance(
        toFixedHex(recipient, 20)
      );
      const ethBalanceRelayerBefore = await web3.eth.getBalance(relayer);
      let isSpent = await tornado.isSpent(toFixedHex(input.nullifierHash));
      isSpent.should.be.equal(false);

      const args = [
        toFixedHex(input.root),
        toFixedHex(input.nullifierHash),
        toFixedHex(input.recipient, 20),
        toFixedHex(input.relayer, 20),
        toFixedHex(input.fee),
        toFixedHex(input.refund),
      ];
      const { logs } = await tornado.withdraw(proof, ...args, {
        value: refund,
        from: relayer,
        gasPrice: "0",
      });

      const balanceTornadoAfter = await token.balanceOf(tornado.address);
      const balanceRelayerAfter = await token.balanceOf(relayer);
      const ethBalanceOperatorAfter = await web3.eth.getBalance(operator);
      const balanceRecieverAfter = await token.balanceOf(
        toFixedHex(recipient, 20)
      );
      const ethBalanceRecieverAfter = await web3.eth.getBalance(
        toFixedHex(recipient, 20)
      );
      const ethBalanceRelayerAfter = await web3.eth.getBalance(relayer);
      const feeBN = toBN(fee.toString());
      balanceTornadoAfter.should.be.eq.BN(
        toBN(balanceTornadoBefore).sub(toBN(tokenDenomination))
      );
      balanceRelayerAfter.should.be.eq.BN(
        toBN(balanceRelayerBefore).add(feeBN)
      );
      balanceRecieverAfter.should.be.eq.BN(
        toBN(balanceRecieverBefore).add(toBN(tokenDenomination).sub(feeBN))
      );

      ethBalanceOperatorAfter.should.be.eq.BN(toBN(ethBalanceOperatorBefore));
      ethBalanceRecieverAfter.should.be.eq.BN(toBN(ethBalanceRecieverBefore));
      ethBalanceRelayerAfter.should.be.eq.BN(toBN(ethBalanceRelayerBefore));

      logs[0].event.should.be.equal("Withdrawal");
      logs[0].args.nullifierHash.should.be.equal(
        toFixedHex(input.nullifierHash)
      );
      logs[0].args.relayer.should.be.eq.BN(relayer);
      logs[0].args.fee.should.be.eq.BN(feeBN);
      isSpent = await tornado.isSpent(toFixedHex(input.nullifierHash));
      isSpent.should.be.equal(true);
    });

    it("should reject with wrong refund value", async () => {
      const deposit = generateDeposit();
      const user = accounts[4];
      await tree.insert(deposit.commitment);
      await token.mint(user, tokenDenomination);
      await token.approve(tornado.address, tokenDenomination, { from: user });
      await tornado.deposit(toFixedHex(deposit.commitment), [], {
        from: user,
        gasPrice: "0",
      });

      const { root, path_elements, path_index } = await tree.path(0);
      // Circuit input
      const input = stringifyBigInts({
        // public
        root,
        nullifierHash: pedersenHash(deposit.nullifier.toBuffer("le", 31)),
        relayer,
        recipient,
        fee,
        refund,

        // private
        nullifier: deposit.nullifier,
        secret: deposit.secret,
        pathElements: path_elements,
        pathIndices: path_index,
      });

      const proofData = await websnarkUtils.genWitnessAndProve(
        groth16,
        input,
        circuit,
        proving_key
      );
      const { proof } = websnarkUtils.toSolidityInput(proofData);

      const args = [
        toFixedHex(input.root),
        toFixedHex(input.nullifierHash),
        toFixedHex(input.recipient, 20),
        toFixedHex(input.relayer, 20),
        toFixedHex(input.fee),
        toFixedHex(input.refund),
      ];
      let { reason } = await tornado.withdraw(proof, ...args, {
        value: 1,
        from: relayer,
        gasPrice: "0",
      }).should.be.rejected;
      reason.should.be.equal(
        "Incorrect refund amount received by the contract"
      );
      ({ reason } = await tornado.withdraw(proof, ...args, {
        value: toBN(refund).mul(toBN(2)),
        from: relayer,
        gasPrice: "0",
      }).should.be.rejected);
      reason.should.be.equal(
        "Incorrect refund amount received by the contract"
      );
    });
  });

  afterEach(async () => {
    await revertSnapshot(snapshotId.result);
    // eslint-disable-next-line require-atomic-updates
    snapshotId = await takeSnapshot();
    tree = new MerkleTree(levels, null, prefix);
  });
});
