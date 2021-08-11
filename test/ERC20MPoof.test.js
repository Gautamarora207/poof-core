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
const Poof = artifacts.require("./ERC20MPoof.sol");
const FeeManager = artifacts.require("./FeeManager.sol");
const BadRecipient = artifacts.require("./BadRecipient.sol");
const Token = artifacts.require("./ERC20Mock.sol");
const AToken = artifacts.require("./AToken.sol");
const LendingPoolCore = artifacts.require("./LendingPoolCore.sol");
const LendingPool = artifacts.require("./LendingPool.sol");

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

contract("ERC20MPoof", (accounts) => {
  let poof;
  let token;
  let aToken;
  let core;
  let pool;
  const sender = accounts[0];
  const operator = accounts[0];
  const levels = 20;
  let tokenDenomination = toWei("1");
  let snapshotId;
  let prefix = "test";
  let tree;
  const celoAmount = toWei("0.1");
  const fee = bigInt(celoAmount).shr(1);
  const refund = celoAmount;
  let recipient = getRandomRecipient();
  const relayer = accounts[1];
  const governance = accounts[2];

  let groth16;
  let circuit;
  let proving_key;

  // Public / private key pair used for encrypting / decrypting the deposit note
  const privateKey = web3.eth.accounts.create().privateKey.slice(2);
  const publicKey = getEncryptionPublicKey(privateKey);

  before(async () => {
    tree = new MerkleTree(levels, null, prefix);
    token = await Token.new();
    aToken = await AToken.new(token.address);
    core = await LendingPoolCore.new(aToken.address);
    await aToken.addMinter(core.address, { from: sender });
    pool = await LendingPool.new(core.address);

    const feeManager = await FeeManager.new(sender);
    const hasher = await Hasher.new();
    const verifier = await Verifier.new();
    await Poof.link(Hasher, hasher.address);
    poof = await Poof.new(
      verifier.address,
      feeManager.address,
      tokenDenomination,
      levels,
      sender,
      token.address,
      governance,
      core.address,
      pool.address
    );

    await token.mint(sender, tokenDenomination);
    snapshotId = await takeSnapshot();
    groth16 = await buildGroth16();
    circuit = require("../build/circuits/withdraw.json");
    proving_key = fs.readFileSync(
      "build/circuits/withdraw_proving_key.bin"
    ).buffer;
  });

  describe("#constructor", () => {
    it("should initialize", async () => {
      const tokenFromContract = await poof.token();
      tokenFromContract.should.be.equal(token.address);
    });
  });

  describe("#deposit", () => {
    it("should work", async () => {
      const commitment = toFixedHex(43);
      await token.approve(poof.address, tokenDenomination);
      const aTokenBalanceBefore = await token.balanceOf(aToken.address);

      let { logs } = await poof.deposit(commitment, [], { from: sender });

      logs[0].event.should.be.equal("Deposit");
      logs[0].args.commitment.should.be.equal(commitment);
      logs[0].args.leafIndex.should.be.eq.BN(0);

      const aTokenBalanceAfter = await token.balanceOf(aToken.address);
      aTokenBalanceAfter
        .sub(aTokenBalanceBefore)
        .should.be.eq.BN(tokenDenomination);
    });

    it("should not allow to send ether on deposit", async () => {
      const commitment = toFixedHex(43);
      await token.approve(poof.address, tokenDenomination);

      let error = await poof.deposit(commitment, [], {
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
      await token.approve(poof.address, tokenDenomination, { from: user });
      // Uncomment to measure gas usage
      // let gas = await poof.deposit.estimateGas(toBN(deposit.commitment.toString()), { from: user, gasPrice: '0' })
      // console.log('deposit gas:', gas)
      const { logs: depositLogs } = await poof.deposit(
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

      const balancePoofBefore = await aToken.balanceOf(poof.address);
      const balanceRelayerBefore = await token.balanceOf(relayer);
      const balanceRecieverBefore = await token.balanceOf(
        toFixedHex(recipient, 20)
      );

      const ethBalanceOperatorBefore = await web3.eth.getBalance(operator);
      const ethBalanceRecieverBefore = await web3.eth.getBalance(
        toFixedHex(recipient, 20)
      );
      const ethBalanceRelayerBefore = await web3.eth.getBalance(relayer);
      let isSpent = await poof.isSpent(toFixedHex(input.nullifierHash));
      isSpent.should.be.equal(false);
      const args = [
        toFixedHex(input.root),
        toFixedHex(input.nullifierHash),
        toFixedHex(input.recipient, 20),
        toFixedHex(input.relayer, 20),
        toFixedHex(input.fee),
        toFixedHex(input.refund),
      ];
      const { logs } = await poof.withdraw(proof, ...args, {
        value: refund,
        from: relayer,
        gasPrice: "0",
      });

      const balancePoofAfter = await aToken.balanceOf(poof.address);
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
      balancePoofAfter.should.be.eq.BN(
        toBN(balancePoofBefore).sub(toBN(tokenDenomination))
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
      isSpent = await poof.isSpent(toFixedHex(input.nullifierHash));
      isSpent.should.be.equal(true);
    });
  });

  describe("#governanceClaim", () => {
    it("should work", async () => {
      await aToken.mint(poof.address, 1000);
      const balancePoofBefore = await aToken.balanceOf(poof.address);
      const balanceGovBefore = await aToken.balanceOf(governance);
      await poof.governanceClaim(aToken.address);
      const balancePoofAfter = await aToken.balanceOf(poof.address);
      const balanceGovAfter = await aToken.balanceOf(governance);

      balancePoofBefore.sub(balancePoofAfter).should.be.eq.BN(toBN("1000"));
      balanceGovAfter.sub(balanceGovBefore).should.be.eq.BN(toBN("1000"));
    });

    it("should not claim more than what users have deposited", async () => {
      // User deposit
      let commitment = toFixedHex(43);
      await token.approve(poof.address, tokenDenomination);
      await poof.deposit(commitment, [], { from: sender });

      // Mint
      await aToken.mint(poof.address, 1000);
      const balancePoofBefore = await aToken.balanceOf(poof.address);
      const balanceGovBefore = await aToken.balanceOf(governance);
      await poof.governanceClaim(aToken.address);
      const balancePoofAfter = await aToken.balanceOf(poof.address);
      const balanceGovAfter = await aToken.balanceOf(governance);

      balancePoofBefore.sub(balancePoofAfter).should.be.eq.BN("1000");
      balanceGovAfter.sub(balanceGovBefore).should.be.eq.BN("1000");
    });

    it("should claim a different ERC20", async () => {
      // User deposit
      let commitment = toFixedHex(43);
      await token.approve(poof.address, tokenDenomination);
      await poof.deposit(commitment, [], { from: sender });

      // Mint token
      await token.mint(poof.address, 1000);
      const balancePoofBefore = await token.balanceOf(poof.address);
      const balanceGovBefore = await token.balanceOf(governance);
      await poof.governanceClaim(token.address);
      const balancePoofAfter = await token.balanceOf(poof.address);
      const balanceGovAfter = await token.balanceOf(governance);

      balancePoofBefore.sub(balancePoofAfter).should.be.eq.BN(toBN("1000"));
      balanceGovAfter.sub(balanceGovBefore).should.be.eq.BN(toBN("1000"));
    });
  });

  afterEach(async () => {
    await revertSnapshot(snapshotId.result);
    // eslint-disable-next-line require-atomic-updates
    snapshotId = await takeSnapshot();
    tree = new MerkleTree(levels, null, prefix);
  });
});
