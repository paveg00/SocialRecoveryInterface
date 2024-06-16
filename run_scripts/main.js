
import { ethers } from "ethers";
import RecoveryModule from "../build/artifacts/src/RecoveryModule.sol/RecoveryModule.json" with { type: "json" };
import OpenIDVerifier from "../build/artifacts/src/verifier/openid/OpenIDVerifier.sol/OpenIDVerifier.json" with { type: "json" };
import SafeWallet from "../build/artifacts/@safe-global/safe-contracts/contracts/Safe.sol/Safe.json" with { type: "json" };
import SafeProxyFactory from "../build/artifacts/@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol/SafeProxyFactory.json" with { type: "json" };

// console.log(JSON.stringify(RecoveryModule.abi))

const provider = new ethers.JsonRpcProvider('http://127.0.0.1:8545/')

const PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const PUB_KEY = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
const signer = new ethers.Wallet(PRIVATE_KEY, provider)
// const CONTRACT_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
// const recoveryModuleContract = new ethers.Contract(
//     CONTRACT_ADDRESS,
//     RecoveryModule.abi,
//     signer
//   )


const RecoveryModuleAddress = '0xA51c1fc2f0D1a1b8494Ed1FE312d7C3a78Ed91C0'
const OpenIdVerifierAddress = '0x0DCd1Bf9A1b36cE34237eEaFef220932846BCD82'
const SafeProxyFactory_ADDRESS = '0x7ec60b29c1c201c7f1c97c42e3edba3e8f905360'
const SafeSingleton_ADDRESS = '0x96bdba93A42B9111D4a5Dbbc3026dB775382aDa2'
const safeProxyFactoryContract = new ethers.Contract(
  SafeProxyFactory_ADDRESS,
  SafeProxyFactory.abi,
  signer
)



const initializer = '0xb63e800d000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb922660000000000000000000000000000000000000000000000000000000000000000'


const openIdVerifierContract = new ethers.Contract(
  OpenIdVerifierAddress,
  OpenIDVerifier.abi,
  signer
)

async function enableModule(walletContract, moduleAddr) {
  const tx = await walletContract.enableModule(moduleAddr)
  const rc = await tx.wait();
  console.log("logs")
  console.log(rc.logs)


}

function RandInteger() {
  return Math.floor(Math.random() * (10000 + 1))
}

async function createSafeWallet() {
  const tx = await safeProxyFactoryContract.createProxyWithNonce(
    SafeSingleton_ADDRESS, initializer, RandInteger())
  // console.log("tx")
  // console.log(tx)
  const rc = await tx.wait();
  // console.log("rc")
  // console.log(rc)
  // console.log("events")
  console.log(rc.logs[1].fragment.name)
  const event = rc.logs.find(event => event.fragment?.name === 'ProxyCreation');
  // console.log("event")
  // console.log(event)
  return event.args[0]
}


async function runEnableModuleTransaction(data, wallet, wallet_addr, signer) {
  console.log('Safe transaction nonce:', await wallet.nonce())
  const nonce = await wallet.nonce()
  const safeTransactionHash = await wallet.getTransactionHash(
    wallet_addr,
    0,
    data,
    0, 0, 0, 0,
    PUB_KEY,
    PUB_KEY,
    nonce
  )
  console.log('Safe transaction hash:', safeTransactionHash)

  // console.log('Safe transaction hash:', rc.logs)
  let s = await signer.signMessage(ethers.getBytes(safeTransactionHash))
  // console.log('Safe transaction sign:', s)
  let t = ethers.getBytes(s)
  const v = t[t.length - 1] + 4
  t[t.length - 1] = v
  s = t
  console.log('Safe transaction sign:', ethers.toQuantity(s))

  const tx = await safeWalletContract.execTransaction(
    wallet_addr,
    0,
    data,
    0, 0, 0, 0,
    PUB_KEY,
    PUB_KEY,
    s
  )
  await tx.wait()
}

async function setAudAndPub() {
  // let abiCoder = new ethers.solidityPacked()
  let audKey = ethers.keccak256(ethers.solidityPacked(
    ['string', 'string'],
    ["https://accounts.google.com", "892021943047-4uss7i965lcnhv9dvhjgd5btm3140b9o.apps.googleusercontent.com"]
  ));
  console.log(audKey)
  let tx = await openIdVerifierContract.addOpenIDAudience(audKey)
  let rc = await tx.wait()
  console.log("addOpenIDAudience")
  console.log(rc)

  let indPubKey = ethers.keccak256(ethers.solidityPacked(
    ['string', 'string'],
    ["https://accounts.google.com", "6719678351a5faedc2e70274bbea62da2a8c4a12"]
  ));
  // let pubKey = ethers.keccak256(ethers.solidityPacked(
  //   ['string', 'string'],
  //   ["https://accounts.google.com", "6719678351a5faedc2e70274bbea62da2a8c4a12"]
  // ));
  let pubKey = '0xa003f93a74b329f90457640c9b65c2baee06f1519104eca12a0fb81f4e16cd8ccfa8cfd39aa8bad15a1df7a253a3b49f3343a819e36796458d8e30569124bae9a94d2ebbd334b8b403e286781b19888166adbb0fe871c97c5ccf77431c8bbf9ed757cd29e71981b0b599ef4fb515c565bf49a6b64614ebc188cc14d2b46f8741966264c58f51c58ce20c0304c638a39518db8f8efd1bdd5d186809143649738b830ceaa83351bd2d134b28d488bb9017bbae8312712d9448f79e2647a83e32c46d072b4fc331392c47f8980f2dfabecce9c427a1115b79ad5dd642373aa654b9f9ca35f994aaf9136be090f007c7d34b674f5fa3f2fdc28797ff97a997a70891'
  // let pubKey = '0xa003f93a74b329f90457640c9b65c2baee06f1519104eca12a0fb81f4e16cd8ccfa8cfd39aa8bad15a1df7a253a3b49f3343a819e36796458d8e30569124bae9a94d2ebbd334b8b403e286781b19888166adbb0fe871c97c5ccf77431c8bbf9ed757cd29e71981b0b599ef4fb515c565bf49a6b64614ebc188cc14d2b46f8741966264c58f51c58ce20c0304c638a39518db8f8efd1bdd5d186809143649738b830ceaa83351bd2d134b28d488bb9017bbae8312712d9448f79e2647a83e32c46d072b4fc331392c47f8980f2dfabecce9c427a1115b79ad5dd642373aa654b9f9ca35f994aaf9136be090f007c7d34b674f5fa3f2fdc28797ff97a997a70891'
  pubKey = ethers.hexlify(pubKey)
  console.log("indPubKey")
  console.log(indPubKey)
  // tx = await openIdVerifierContract.updateOpenIDPublicKey(indPubKey, pubKey)
  // rc = await tx.wait()
  // console.log(rc)
  // console.log("updateOpenIDPublicKey")
}



// Создать смарт-кошелек

const wallet_addr = await createSafeWallet()
const safeWalletContract = new ethers.Contract(
  wallet_addr,
  SafeWallet.abi,
  signer
)
console.log("safe wallet addr")
console.log(wallet_addr)
console.log("Nonce", await safeWalletContract.nonce())
console.log("isOwner", await safeWalletContract.isOwner(PUB_KEY))

console.log("enableWallet", await safeWalletContract.isModuleEnabled(RecoveryModuleAddress))

// Включить модуль в смарт-кошельке
const dataEnableModule = safeWalletContract.interface.encodeFunctionData('enableModule', [RecoveryModuleAddress])
await runEnableModuleTransaction(dataEnableModule, safeWalletContract, wallet_addr, signer)
console.log("enableModule", await safeWalletContract.isModuleEnabled(RecoveryModuleAddress))

// Добавить в модуль публичные ключи /addOpenIDAudience /updateOpenIDPublicKey - moduleOwner
// await setAudAndPub()

// Добавить хеш обновления конфигов в смарт кошельке /addConfigs

// const a = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
// const b = '123123123123132123123';
// const c = true;


// struct ThresholdConfig {
//   uint64 threshold; // Threshold value
//   uint48 lockPeriod; // Lock period for the threshold
// }
// const thresholdConfig = ethers.solidityPacked(
//   ['uint64', 'uint48'],
//   [1, 0]
// );

// abi.encodePacked(
//   keccak256(
//       abi.encodePacked(
//           keccak256("https://accounts.google.com"),
//           keccak256("109956066558145320273")
//       )
//   )
// )
// const sign = ethers.solidityPacked(ethers.keccak256(ethers.solidityPacked(
//   ['bytes32']
//   []
// )))
// 0x00ceabc0c2fbcb2ec646ae00b206aa0c88d2a1d12f837882c6e3cae62594754c
// let sign = ethers.solidityPacked(
//   ['bytes32'],
//   [ethers.keccak256(
//       ethers.solidityPacked(
//         ['bytes32', 'bytes32'],
//         [
//           ethers.keccak256(ethers.toUtf8Bytes("https://accounts.google.com")),
//           ethers.keccak256(ethers.toUtf8Bytes("109956066558145320273"))
//         ]
//       )
//     )
//   ]
// )

// ethers.StructFragment


// struct Identity {
//   address guardianVerifier;
//   bytes signer;
// }
// const identity = ethers.solidityPacked(
//   ['address', 'bytes'],
//   [PUB_KEY, sign]
// )

// struct GuardianInfo {
//   Identity guardian;
//   uint64 property; //eg.,Weight,Percentage,Role with weight,etc.
// }
// const guardianInfo = ethers.solidityPacked(
//   ['tuple(address, bytes)', 'uint64'],
//   [[PUB_KEY, sign], 1]
// )

// struct RecoveryConfigArg {
//   address policyVerifier;
//   GuardianInfo[] guardianInfos;
//   ThresholdConfig[] thresholdConfigs;
// }
// recoveryConfigArg = ethers.solidityPacked(
//   ['address', 'tuple()', 'tuple()']
// )

// Обновить конфиги опекнов в смарт кошельке /executeConfigsUpdate

// /startRecovery

console.log("Finished")














