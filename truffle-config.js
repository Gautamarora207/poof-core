require("dotenv").config();
const HDWalletProvider = require("@truffle/hdwallet-provider");
const utils = require("web3-utils");

// const ContractKit = require("@celo/contractkit");
// const Web3 = require("web3");

// // Connect to the desired network
// const web3 = new Web3(process.env.RPC_URL);
// const kit = ContractKit.newKitFromWeb3(web3);
// kit.addAccount(process.env.PRIVATE_KEY);

module.exports = {
  contracts_directory: './contracts/',
  contracts_build_directory: './abis/',
  /**
   * Networks define how you connect to your ethereum client and let you set the
   * defaults web3 uses to send transactions. If you don't specify one truffle
   * will spin up a development blockchain for you on port 9545 when you
   * run `develop` or `test`. You can ask a truffle command to use a specific
   * network from the command line, e.g
   *
   * $ truffle test --network <network-name>
   */

  networks: {
    // Useful for testing. The `development` name is special - truffle uses it by default
    // if it's defined here and no other network is specified at the command line.
    // You should run a client (like ganache-cli, geth or parity) in a separate terminal
    // tab if you use this network and you must also set the `host`, `port` and `network_id`
    // options below to some value.

    development: {
      host: "127.0.0.1", // Localhost (default: none)
      port: 8545, // Standard Ethereum port (default: none)
      network_id: "*", // Any network (default: none)
    },

    rinkeby: {
      provider: () =>
        new HDWalletProvider(
          process.env.MNEMONIC,
          `wss://rinkeby.infura.io/ws/v3/${process.env.INFURA_API_KEY}`
        ),
      network_id: 4,
      gas: 5000000,
      gasPrice: utils.toWei("1", "gwei"),
      // confirmations: 0,
      // timeoutBlocks: 200,
      skipDryRun: true,
    },
  },

  // Set default mocha options here, use special reporters etc.
  mocha: {
    // timeout: 100000
  },

  // Configure your compilers
  compilers: {
    solc: {
      version: "0.5.17", // Fetch exact version from solc-bin (default: truffle's version)
      // docker: true,        // Use "0.5.1" you've installed locally with docker (default: false)
      settings: {
        // See the solidity docs for advice about optimization and evmVersion
        optimizer: {
          enabled: true,
          runs: 200,
        },
        // evmVersion: "byzantium"
      },
    },
    external: {
      command: "node ./compileHasher.js",
      targets: [
        {
          path: "./build/Hasher.json",
        },
      ],
    },
  },
};
