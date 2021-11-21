/* global artifacts */
const FeeManager = artifacts.require("FeeManager");

module.exports = async function (deployer) {
  const accounts = await web3.eth.getAccounts();
  deployer.deploy(FeeManager, accounts[0]);
};
