// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/RecoveryModule.sol";
import "../src/test/TestAccount.sol";
import "../src/TypesAndDecoders.sol";
import "../src/interfaces/IPermissionVerifier.sol";
import "../src/verifier/openid/OpenIDVerifier.sol";

import "@safe-global/safe-contracts/contracts/Safe.sol";
import "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";

contract OpenIDSocialRecoveryTest is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_SEPARATOR_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    bytes32 internal constant _START_RECOVERY_TYPEHASH =
        keccak256(
            "startRecovery(address account,bytes newOwner,uint256 nonce)"
        );

    bytes32 internal constant _CANCEL_RECOVERY_TYPEHASH =
        keccak256("cancelRecovery(address account,uint256 nonce)");

    function getChainID() internal view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    /// @notice             returns the domainSeparator for EIP-712 signature
    /// @return             the bytes32 domainSeparator for EIP-712 signature
    function domainSeparator() public view returns (bytes32) {
        console2.log("Recovery Module");
        console2.logBytes32(keccak256(abi.encodePacked("Recovery Module")));
        console2.log("getChainID()", getChainID());
        console2.log("address(_recoveryModule)", address(_recoveryModule));
        // console2.log(_recoveryModule);
        
        bytes32 domain_separator = keccak256(
            abi.encode(
                _DOMAIN_SEPARATOR_TYPEHASH,
                keccak256(abi.encodePacked("Recovery Module")),
                keccak256(abi.encodePacked("0.0.1")),
                getChainID(),
                address(_recoveryModule)
            )
        );
        console2.log("domain_separator");
        console2.logBytes32(domain_separator);
        return domain_separator;
    }

    RecoveryModule _recoveryModule;
    SafeProxyFactory _factory;
    TestAccount _accountImpl;
    ISafe _account;
    OpenIDVerifier _verifier;

    uint256 _owner;
    address _ownerAddr;

    uint256 _newOwner;
    address _newOwnerAddr;

    uint256 _admin;
    address _adminAddr;

    RecoveryConfigArg configArg;
    uint256 _guardianCount;
    uint256 _threshold;
    uint256 _lockPeriod;

    function setUp() public {
        _guardianCount = 3;
        _threshold = 2;
        _lockPeriod = 1024;
        _recoveryModule = new RecoveryModule();
        _factory = new SafeProxyFactory();
        _accountImpl = new TestAccount();

        _admin = 0x99;
        _adminAddr = vm.addr(_admin);
        vm.startPrank(_adminAddr);
        _verifier = new OpenIDVerifier();
        _verifier.addOpenIDAudience(
            keccak256(
                abi.encodePacked(
                    "https://accounts.google.com",
                    "892021943047-4uss7i965lcnhv9dvhjgd5btm3140b9o.apps.googleusercontent.com"
                )
            )
        );
        _verifier.updateOpenIDPublicKey(
            keccak256(
                abi.encodePacked(
                    "https://accounts.google.com",
                    "6719678351a5faedc2e70274bbea62da2a8c4a12"
                )
            ),
            hex"a003f93a74b329f90457640c9b65c2baee06f1519104eca12a0fb81f4e16cd8ccfa8cfd39aa8bad15a1df7a253a3b49f3343a819e36796458d8e30569124bae9a94d2ebbd334b8b403e286781b19888166adbb0fe871c97c5ccf77431c8bbf9ed757cd29e71981b0b599ef4fb515c565bf49a6b64614ebc188cc14d2b46f8741966264c58f51c58ce20c0304c638a39518db8f8efd1bdd5d186809143649738b830ceaa83351bd2d134b28d488bb9017bbae8312712d9448f79e2647a83e32c46d072b4fc331392c47f8980f2dfabecce9c427a1115b79ad5dd642373aa654b9f9ca35f994aaf9136be090f007c7d34b674f5fa3f2fdc28797ff97a997a70891"
        );
        _verifier.updateOpenIDPublicKey(
            keccak256(
                abi.encodePacked(
                    "https://accounts.google.com",
                    "674dbba8faee69acae1bc1be190453678f472803"
                )
            ),
            hex"c3e97f544e0a35adb69f89ec33071a6ee8e8c26f76e18a10427c0ecff74f6079832353beaf66eac3a987981c97c228bb69a7883072595a9993e52911dce608bb945b4a0894fbc26b428a655bfbd963622a1b5cb9f9facf0bff609f3ff4a8a2a3b63aa09423fed4095f39dbbbaf990ea643800ace665a7e2d9b52bd47510f8e4d93fcc30eec592d79977cc288757f0514baf6e13f20f1073c7d114b271966e94e774e61ced6f84524d6332d5819376ee2de6b2a5568e2d6ada9cafd716b5fec71d3706886b7e29ceaa67ed620734cfde2cc62c7b5f51b7e8965e87cfa3a54870c813e29c1c4e64e13fe64427e0260ceba620c708b0b34649fa4946daa4e2db7f7"
        );

        // d1b83f8a96f95e42651b74bd506dc6f6e91f1da5efcc4751c9d5c4973ba3654f1ebfc5b4d3e1a75d05f90050a0c8c69f95fe9cf95d33005c2ce50141e8af13406d668f0f587e982e723c48f63a15435c70913856345d34bd05ff9d4854cb106d51d5294372550e742ef89372e77c94b5bf46d9216ddfd13646a3ba0d06d33f8b81e10c7b8864d314028a7ba74227dc5dd9c1828ce06bedaa0d58c5200c7c13c4581c8578a4504dfc6763039af65ff231651a03fe069a3e4f15800bc52f87a075007efd63b9d761fc9b1029ea6f04b2c3fc240cd69519c0e74df6166345bc30e9c5a23b1f929d7d065f91ce12d3c0377212d78a309add8c70a3b56b922814dd83
        // da8c6794ed334a12a2520eb72a4b2db2cae3a040e759dd38a9f565a1e138201249bcfe8304cbcb58c3c07b4621cd302d318aaa6c7b674bb7f47dc93a8c39715777d84ed8727c3f87722b25883d73c6fa8f5100bf2ccda1ff79244aba07c461255315ec0c416b6bb446406ba4c7f269191580b8cf84e03e93422139ea49f14f9e6994ca009ebcf636a22e49687ca17c8cff0a392a22a369386ae37db94ca0c1e08d53c4c35964d9f61dd746fdbe9949cb28bd01ad34ac60b05ea21aab561e07018821036718b598cb05fea57ae0b58eabdd420fca8bfd20299db86a018318cefcfbbf741f674b4403261fd51d8526aa48aa7bbe6549f8f86f9b970803318440b7
        vm.stopPrank();

        _owner = 0x100;
        _ownerAddr = vm.addr(_owner);
        address[] memory owners = new address[](1);
        owners[0] = _ownerAddr;
        owners[0] = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);

        bytes memory initializer = abi.encodeCall(
            Safe.setup,
            (
                owners,
                1,
                address(0),
                hex"",
                address(0),
                address(0),
                0,
                payable(address(0))
            )
        );
        console2.log("INITIALIZER");
        console2.logBytes(initializer);

        _account = ISafe(
            address(
                _factory.createProxyWithNonce(
                    address(_accountImpl),
                    initializer,
                    0
                )
            )
        );

        vm.startPrank(address(_account));
        _account.enableModule(address(_recoveryModule));

        ThresholdConfig memory thresholdConfig0;
        thresholdConfig0.threshold = uint64(_guardianCount);
        thresholdConfig0.lockPeriod = 0;
        configArg.thresholdConfigs.push(thresholdConfig0);

        ThresholdConfig memory thresholdConfig1;
        thresholdConfig1.threshold = uint64(_threshold);
        thresholdConfig1.lockPeriod = uint48(_lockPeriod);
        configArg.thresholdConfigs.push(thresholdConfig1);

        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(
                keccak256(
                    abi.encodePacked(
                        keccak256("https://accounts.google.com"),
                        keccak256("109956066558145320273")
                    )
                )
            );
            guardian.guardian = id;
            guardian.property = 1;
            configArg.guardianInfos.push(guardian);
        }
        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(
                keccak256(
                    abi.encodePacked(
                        keccak256("test_issuer"),
                        keccak256("test_user2")
                    )
                )
            );
            guardian.guardian = id;
            guardian.property = 1;
            configArg.guardianInfos.push(guardian);
        }
        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(
                keccak256(
                    abi.encodePacked(
                        keccak256("test_issuer"),
                        keccak256("test_user3")
                    )
                )
            );
            guardian.guardian = id;
            guardian.property = 1;
            configArg.guardianInfos.push(guardian);
        }

        RecoveryConfigArg[] memory configArgs = new RecoveryConfigArg[](1);
        configArgs[0] = configArg;
        bytes32 configsHash = keccak256(abi.encode(configArgs));
        _recoveryModule.addConfigs(configsHash);

        vm.warp(27173519770);
        _recoveryModule.executeConfigsUpdate(address(_account), configArgs);
        vm.stopPrank();

        console2.log("domainSeparator: ");
        console2.logBytes32(domainSeparator());
        console2.log("Timestamp: ");
        console2.log(block.timestamp);
    }

    function testOpenIDInstantRecovery1() public {
        _newOwner = 0x101;
        _newOwnerAddr = vm.addr(_newOwner);
        bytes memory data = abi.encodeCall(
            OwnerManager.swapOwner,
            (address(0x1), _ownerAddr, _newOwnerAddr)
        );
        console2.log("data");
        console2.logAddress(_ownerAddr);
        console2.logAddress(_newOwnerAddr);
        console2.logBytes(data);

        console2.log(
            "walletRecoveryNonce",
            _recoveryModule.walletRecoveryNonce(address(_account))
        );

        console2.log("wallet");
        console2.logAddress(address(_account));
        console2.log("domainSeparator()");
        console2.logBytes32(domainSeparator());

        bytes32 payload = 
        keccak256(
                    abi.encode(
                        _START_RECOVERY_TYPEHASH,
                        address(_account),
                        data,
                        _recoveryModule.walletRecoveryNonce(address(_account)) +
                            1
                    )
                );
        // console2.log("payload: ");
        // console2.logBytes(payload);

        bytes32 digest = 
        keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator(),
                keccak256(
                    abi.encode(
                        _START_RECOVERY_TYPEHASH,
                        address(_account),
                        data,
                        _recoveryModule.walletRecoveryNonce(address(_account)) +
                            1
                    )
                )
            )
        );

        console2.log("digest: ");
        console2.logBytes32(digest);

        Permission[] memory permissions = new Permission[](_guardianCount);
        // {
        //     Identity memory id;
        //     id.guardianVerifier = configArg
        //         .guardianInfos[0]
        //         .guardian
        //         .guardianVerifier;
        //     id.signer = configArg.guardianInfos[0].guardian.signer;
        //     permissions[0].guardian = id;
        //     permissions[0]
        //         .signature = hex"0000003b00000056000000160000003e0000005f000000740000007d000000c5000000d000000007000000180000004c7b22616c67223a225253323536222c226b6964223a2236373464626261386661656536396163616531626331626531393034353336373866343732383033222c22747970223a224a5754227d000001147b22696174223a313731373335353636322c22657870223a313731373434323036322c226e6266223a313731373335353636322c22697373223a2268747470733a2f2f6163636f756e74732e676f6f676c652e636f6d222c22737562223a22313039393536303636353538313435333230323733222c22617564223a223839323032313934333034372d3475737337693936356c636e6876396476686a67643562746d3331343062396f2e617070732e676f6f676c6575736572636f6e74656e742e636f6d222c226e6f6e6365223a22307836336466613837663461316632666666393963326635613861333365373866643565656364343733616265333739333562393332663439613931336535343531227d00000100bae5c2444946d11039e29f51030a1f878c06a053bc1d6beb524b9b4f613ab25ff5945ba3f2289a23ed589598e01db7d23a37c278c4ca9b1abf975669a459ea3459dadf369d5f6d3aba4fca29b07a6d235498618cacd9a112dec0037af76db006cb81548a354c122689e4e41bfd1a3cf382dc3dda56293cdb4f835af782658c7d2c46830852669cfbbf22d7f0884c3f645a9bad9547eba391b1570641ec107f166f2d31b5b265c6a95155e5ba3b5fa9d930cc79fcd6c3159b10f5a57549cf235ad709d251ec1409fc7917ee9826d24ce1834e74d2433e8bdbdfbf40f5c4c56c1bea89c01c3ba1d111cbbc2bf40a012b20d72b4a2104e12cbb73e6e54fcf9c144c";
        // }
        {
            Identity memory id;
            id.guardianVerifier = configArg
                .guardianInfos[0]
                .guardian
                .guardianVerifier;
            id.signer = configArg.guardianInfos[0].guardian.signer;
            permissions[0].guardian = id;
            permissions[0]
                .signature = hex"0000000800000023000000160000003e000000ce000000e30000007d000000c5000001110000015b0000016c0000004c7b22616c67223a225253323536222c226b6964223a2236373464626261386661656536396163616531626331626531393034353336373866343732383033222c22747970223a224a5754227d000001777b22697373223a2268747470733a2f2f6163636f756e74732e676f6f676c652e636f6d222c22617a70223a223839323032313934333034372d3475737337693936356c636e6876396476686a67643562746d3331343062396f2e617070732e676f6f676c6575736572636f6e74656e742e636f6d222c22617564223a223839323032313934333034372d3475737337693936356c636e6876396476686a67643562746d3331343062396f2e617070732e676f6f676c6575736572636f6e74656e742e636f6d222c22737562223a22313039393536303636353538313435333230323733222c2261745f68617368223a22797761587545375136425f454d644d56326650726641222c226e6f6e6365223a22307836336466613837663461316632666666393963326635613861333365373866643565656364343733616265333739333562393332663439613931336535343531222c22696174223a313731373336323638312c22657870223a313731373336363238317d000001005fd572dca0b8a82dda636b5bd3a2a27f580db9f6dbd64d16320ab4719d6e7d761ee34ec3306eb9e45c4abd5919c7c671cf8bc712c7307ade1e13d0e7f0f2ce1ac8f7908510c5e59e7948e81c9153441135738beef084177116084c873f44b37800bfbd54c1508b0517332e20b868d1907fad5d35ea11316a66114a88011ac5215ccfa20fe62b860deda54b36708568067ee998aa5db9c5b4b4abe55954102281e33fc12802f1924536d6c5011efddeab599447ea42acf915bdf3b5e35e4f5acb6fb18753a9c553cc88862a511792f748fe2d5e1a97aac9e228d321b8982228f0d4a2dbcc70e1404cf4fcea2792ea2fbfaed5f777b974a6881b9f3dabcd32c261";
        }
        {
            Identity memory id;
            id.guardianVerifier = configArg
                .guardianInfos[1]
                .guardian
                .guardianVerifier;
            id.signer = configArg.guardianInfos[1].guardian.signer;
            permissions[1].guardian = id;
            permissions[1]
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730323938323138312c22657870223a313730333036383538312c226e6266223a313730323938323138312c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657232222c22617564223a22746573745f617564222c226e6f6e6365223a22307830313166616439346233336564666630303866393636633933633662616235336132343436383238623566303932343637303332336164306666303563336331227d000001001449f4c36979a3d4bda9b440370561fa97aa569c328b8e229088ee250510a13ed7720bb40ae82ef90235d160da4663b85b1c02c19108f1c440f14bc6ec005a0f680ff715f2954eb15d18c11940080c755d060b5dc0a3608b1cddcd10b1a30bc5c1a2128d7a1109b99c9cd6995e24493e04f7852a5e9e2e24f79f1b3246133b7aee69c9d933fbe72e0f04ebfcf185ea7b0055477aa168c6f220e530ad23355b7b247bf8a2d1d21c1fb6875af8859cfbb8fdceea5c22116dbeb750b0e48cde9ee88fdfec73a2e0e69b4b7651b5b30dd9f3cd54f4f286efda322c31e1d4cecc74b7aa2edf9ce24df87b4b5cb871217ca6356d358634a92db4a320f912452a3ca26a";
        }
        {
            Identity memory id;
            id.guardianVerifier = configArg
                .guardianInfos[2]
                .guardian
                .guardianVerifier;
            id.signer = configArg.guardianInfos[2].guardian.signer;
            permissions[2].guardian = id;
            permissions[2]
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730323938323138332c22657870223a313730333036383538332c226e6266223a313730323938323138332c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657233222c22617564223a22746573745f617564222c226e6f6e6365223a22307830313166616439346233336564666630303866393636633933633662616235336132343436383238623566303932343637303332336164306666303563336331227d000001002cbf36e014c8fe215e2bc3fca77c3a485d4cacea956370763ad9e9c2600cfe90df45f162479a4792c521154f46080eb5388c956a862fe81569298caac0b9673d4e6818f62e78da9a304e2f6aeae4219061f99f7c74877c41287c44afab5a723a854da5c02ca58bc8e4af99a2f1b666960ff62f34593e44abd728da2aa82db519a355b1a9d6868fb2670d1ef68c6d28bf97e2444b65cf0f4228f138c6d132be22fc786f51a6f877dccde3e54ec70cda5e1f3e30b82d750b716f86f4aa6cb884ca4fe5b43e0d27ab9ba39228898760a4409e5a5befe53bd716fcffe18b1d3520bfabf967f16b5189f337f4c3833f00aa5281b8ce5892d130f362335669f5a1e51c";
        }

        vm.warp(1717362786);
        _recoveryModule.startRecovery(address(_account), 0, data, permissions);
    }
}
