import "@nomicfoundation/hardhat-toolbox";
import type { HardhatUserConfig, HttpNetworkUserConfig } from "hardhat/types";
import "hardhat-deploy";
import dotenv from "dotenv";
import yargs from "yargs";
import "@nomicfoundation/hardhat-foundry"
import { getSingletonFactoryInfo } from "@safe-global/safe-singleton-factory";
import "hardhat-ethernal";

const argv = yargs
    .option("network", {
        type: "string",
        default: "hardhat",
    })
    .help(false)
    .version(false)
    .parseSync();

// Load environment variables.
dotenv.config();
const { NODE_URL, INFURA_KEY, MNEMONIC, ETHERSCAN_API_KEY, PK, SOLIDITY_VERSION, SOLIDITY_SETTINGS } = process.env;

const DEFAULT_MNEMONIC = "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat";

const sharedNetworkConfig: HttpNetworkUserConfig = {};
if (PK) {
    sharedNetworkConfig.accounts = [PK];
} else {
    sharedNetworkConfig.accounts = {
        mnemonic: MNEMONIC || DEFAULT_MNEMONIC,
    };
}

if (["mainnet", "rinkeby", "kovan", "goerli", "ropsten", "mumbai", "polygon"].includes(argv.network) && INFURA_KEY === undefined) {
    throw new Error(`Could not find Infura key in env, unable to connect to network ${argv.network}`);
}

// import "./src/tasks/local_verify";
// import "./src/tasks/deploy_contracts";
// import "./src/tasks/show_codesize";
import { BigNumber } from "@ethersproject/bignumber";
import { DeterministicDeploymentInfo } from "hardhat-deploy/dist/types";
import { ethers } from "ethers";

const defaultSolidityVersion = "0.8.19";
const primarySolidityVersion = SOLIDITY_VERSION || defaultSolidityVersion;
const soliditySettings = SOLIDITY_SETTINGS ? JSON.parse(SOLIDITY_SETTINGS) : undefined;

const deterministicDeployment = (network: string): DeterministicDeploymentInfo => {
    const info = getSingletonFactoryInfo(parseInt(network));
    if (!info) {
        throw new Error(`
        Safe factory not found for network ${network}. You can request a new deployment at https://github.com/safe-global/safe-singleton-factory.
        For more information, see https://github.com/safe-global/safe-smart-account#replay-protection-eip-155
      `);
    }
    return {
        factory: info.address,
        deployer: info.signerAddress,
        funding: BigNumber.from(info.gasLimit).mul(BigNumber.from(info.gasPrice)).toString(),
        signedTx: info.transaction,
    };
};

const userConfig: HardhatUserConfig = {
    paths: {
        artifacts: "build/artifacts",
        cache: "build/cache",
        deploy: "deploy/deploy",
        sources: "src",
    },
    typechain: {
        outDir: "typechain-types",
        target: "ethers-v6",
    },
    solidity: {
        compilers: [{ version: primarySolidityVersion, settings: soliditySettings }, { version: defaultSolidityVersion }],
    },
    networks: {
        localhost: {
            url: `http://127.0.0.1:8545/`,
            allowUnlimitedContractSize: true,
            blockGasLimit: 100000000,
            gas: 100000000,
        },
        hardhat: {
            allowUnlimitedContractSize: true,
            blockGasLimit: 100000000,
            gas: 100000000,
        }
    },
    deterministicDeployment,
    mocha: {
        timeout: 2000000,
    },
    namedAccounts: {
        deployer: 0,
    },
    ethernal: {
        disableSync: false, // If set to true, plugin will not sync blocks & txs
        disableTrace: false, // If set to true, plugin won't trace transaction
        workspace: undefined, // Set the workspace to use, will default to the default workspace (latest one used in the dashboard). It is also possible to set it through the ETHERNAL_WORKSPACE env variable
        uploadAst: true, // If set to true, plugin will upload AST, and you'll be able to use the storage feature (longer sync time though)
        disabled: false, // If set to true, the plugin will be disabled, nohting will be synced, ethernal.push won't do anything either
        resetOnStart: undefined, // Pass a workspace name to reset it automatically when restarting the node, note that if the workspace doesn't exist it won't error
        serverSync: false, // Only available on public explorer plans - If set to true, blocks & txs will be synced by the server. For this to work, your chain needs to be accessible from the internet. Also, trace won't be synced for now when this is enabled.
        skipFirstBlock: false, // If set to true, the first block will be skipped. This is mostly useful to avoid having the first block synced with its tx when starting a mainnet fork
        verbose: false, // If set to true, will display this config object on start and the full error object
        apiToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJlYmFzZVVzZXJJZCI6IjhLZnJZc1pKNzlOYWJLamQ3V3pzT2xGRG0xNDIiLCJhcGlLZXkiOiJFQjU5QUJTLTAzWjQzNjUtTkVENlpWUS1EMU44WDVSXHUwMDAxIiwiaWF0IjoxNzE3ODU2NDg4fQ.q3CFtJFIILgOrSvgX89HMS2u9DiccBQaGqXx6dq0hVc",
    },
};
if (NODE_URL) {
    userConfig.networks!.custom = {
        ...sharedNetworkConfig,
        url: NODE_URL,
    };
}
export default userConfig;
