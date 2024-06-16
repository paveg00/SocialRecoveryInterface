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
        return
            keccak256(
                abi.encode(
                    _DOMAIN_SEPARATOR_TYPEHASH,
                    keccak256(abi.encodePacked("Recovery Module")),
                    keccak256(abi.encodePacked("0.0.1")),
                    getChainID(),
                    address(_recoveryModule)
                )
            );
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
            keccak256(abi.encodePacked("https://accounts.google.com", "892021943047-4uss7i965lcnhv9dvhjgd5btm3140b9o.apps.googleusercontent.com"))
        );
        console2.log("addOpenIDAudience: ");
        console2.logBytes32(keccak256(abi.encodePacked("https://accounts.google.com", "892021943047-4uss7i965lcnhv9dvhjgd5btm3140b9o.apps.googleusercontent.com")));
        _verifier.updateOpenIDPublicKey(
            keccak256(abi.encodePacked("https://accounts.google.com", "6719678351a5faedc2e70274bbea62da2a8c4a12")),
            hex"a003f93a74b329f90457640c9b65c2baee06f1519104eca12a0fb81f4e16cd8ccfa8cfd39aa8bad15a1df7a253a3b49f3343a819e36796458d8e30569124bae9a94d2ebbd334b8b403e286781b19888166adbb0fe871c97c5ccf77431c8bbf9ed757cd29e71981b0b599ef4fb515c565bf49a6b64614ebc188cc14d2b46f8741966264c58f51c58ce20c0304c638a39518db8f8efd1bdd5d186809143649738b830ceaa83351bd2d134b28d488bb9017bbae8312712d9448f79e2647a83e32c46d072b4fc331392c47f8980f2dfabecce9c427a1115b79ad5dd642373aa654b9f9ca35f994aaf9136be090f007c7d34b674f5fa3f2fdc28797ff97a997a70891"
        );
        // d1b83f8a96f95e42651b74bd506dc6f6e91f1da5efcc4751c9d5c4973ba3654f1ebfc5b4d3e1a75d05f90050a0c8c69f95fe9cf95d33005c2ce50141e8af13406d668f0f587e982e723c48f63a15435c70913856345d34bd05ff9d4854cb106d51d5294372550e742ef89372e77c94b5bf46d9216ddfd13646a3ba0d06d33f8b81e10c7b8864d314028a7ba74227dc5dd9c1828ce06bedaa0d58c5200c7c13c4581c8578a4504dfc6763039af65ff231651a03fe069a3e4f15800bc52f87a075007efd63b9d761fc9b1029ea6f04b2c3fc240cd69519c0e74df6166345bc30e9c5a23b1f929d7d065f91ce12d3c0377212d78a309add8c70a3b56b922814dd83
        // a003f93a74b329f90457640c9b65c2baee06f1519104eca12a0fb81f4e16cd8ccfa8cfd39aa8bad15a1df7a253a3b49f3343a819e36796458d8e30569124bae9a94d2ebbd334b8b403e286781b19888166adbb0fe871c97c5ccf77431c8bbf9ed757cd29e71981b0b599ef4fb515c565bf49a6b64614ebc188cc14d2b46f8741966264c58f51c58ce20c0304c638a39518db8f8efd1bdd5d186809143649738b830ceaa83351bd2d134b28d488bb9017bbae8312712d9448f79e2647a83e32c46d072b4fc331392c47f8980f2dfabecce9c427a1115b79ad5dd642373aa654b9f9ca35f994aaf9136be090f007c7d34b674f5fa3f2fdc28797ff97a997a70891
        // 6f4150354f6e537a4b666b455632514d6d3258437575344738564752424f79684b672d34483034577a597a50714d5f546d71693630566f6439364a546f3753664d304f6f47654e6e6c6b574e6a6a42576b53533636616c4e4c7276544e4c6930412d4b476542735a6949466d726273503648484a66467a5064304d6369372d653131664e4b65635a676243316d653950745258465a62394a70725a47464f7642694d77553072527668304757596d54466a3148466a4f494d417754474f4b4f56474e75506a7630623356305961416b554e6b6c7a69344d4d3671677a556230744530736f314969376b426537726f4d5363533255535065654a6b656f506a4c456251637254384d784f5378482d4a67504c66712d7a4f6e454a36455257336d7458645a434e7a716d564c6e35796a58356c4b7235453276676b50414878394e4c5a3039666f5f4c39776f65585f3565706c3663496b51
        // oAP5OnSzKfkEV2QMm2XCuu4G8VGRBOyhKg-4H04WzYzPqM_Tmqi60Vod96JTo7SfM0OoGeNnlkWNjjBWkSS66alNLrvTNLi0A-KGeBsZiIFmrbsP6HHJfFzPd0Mci7-e11fNKecZgbC1me9PtRXFZb9JprZGFOvBiMwU0rRvh0GWYmTFj1HFjOIMAwTGOKOVGNuPjv0b3V0YaAkUNklzi4MM6qgzUb0tE0so1Ii7kBe7roMScS2USPeeJkeoPjLEbQcrT8MxOSxH-JgPLfq-zOnEJ6ERW3mtXdZCNzqmVLn5yjX5lKr5E2vgkPAHx9NLZ09fo_L9woeX_5epl6cIkQ
        _verifier.updateOpenIDPublicKey(
            keccak256(abi.encodePacked("https://accounts.google.com", "674dbba8faee69acae1bc1be190453678f472803")),
            hex"c3e97f544e0a35adb69f89ec33071a6ee8e8c26f76e18a10427c0ecff74f6079832353beaf66eac3a987981c97c228bb69a7883072595a9993e52911dce608bb945b4a0894fbc26b428a655bfbd963622a1b5cb9f9facf0bff609f3ff4a8a2a3b63aa09423fed4095f39dbbbaf990ea643800ace665a7e2d9b52bd47510f8e4d93fcc30eec592d79977cc288757f0514baf6e13f20f1073c7d114b271966e94e774e61ced6f84524d6332d5819376ee2de6b2a5568e2d6ada9cafd716b5fec71d3706886b7e29ceaa67ed620734cfde2cc62c7b5f51b7e8965e87cfa3a54870c813e29c1c4e64e13fe64427e0260ceba620c708b0b34649fa4946daa4e2db7f7"
        );
        vm.stopPrank();

        _owner = 0x100;
        _ownerAddr = vm.addr(_owner);
        address[] memory owners = new address[](1);
        owners[0] = _ownerAddr;

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
            console2.log("Signer");
            // console.logBytes(id);
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
                        keccak256("https://accounts.google.com"),
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
                        keccak256("https://accounts.google.com"),
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
        console2.log("Configs");
        // console2.log(configArgs[0]);
        console2.logBytes32(configsHash);

        _recoveryModule.addConfigs(configsHash);

        vm.warp(block.timestamp + 3 days);
        _recoveryModule.executeConfigsUpdate(address(_account), configArgs);
        vm.stopPrank();

        console2.log("domainSeparator: ");
        console2.logBytes32(domainSeparator());
    }

    function testOpenIDInstantRecovery2() public {
        _newOwner = 0x101;
        _newOwnerAddr = vm.addr(_newOwner);
        bytes memory data = abi.encodeCall(
            OwnerManager.swapOwner,
            (address(0x1), _ownerAddr, _newOwnerAddr)
        );

        bytes32 digest = keccak256(
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
        {
            Identity memory id;
            id.guardianVerifier = configArg
                .guardianInfos[0]
                .guardian
                .guardianVerifier;
            id.signer = configArg.guardianInfos[0].guardian.signer;
            permissions[0].guardian = id;
            permissions[0]
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730323938323137382c22657870223a313730333036383537382c226e6266223a313730323938323137382c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657231222c22617564223a22746573745f617564222c226e6f6e6365223a22307830313166616439346233336564666630303866393636633933633662616235336132343436383238623566303932343637303332336164306666303563336331227d0000010041a4b10600ca7472fb9691b140c4f45d9bb9be5ff2786664648a792ae6ef82f1d2eefc66aae89f5a3af46e8bc7cb8ee340c33f78239e50ce56e55346dc14f3137e54daf7a3b0122ca433bebbfe1e40903e7b0636826cc4eeccba38fc48d75386864503a0f0f5a854fd10632997bb93bfc81b420c60bb781d94eca5cdc4985b8e15533e7cc0dfdfec352623142cb317bc91d9f938ecea9dabb3f8a37f69836eaf33b8c3d800bbdce80f7a29a02dbf3c87bc09d34fb4c0fd07eb46830391a7b3c594290e3562510db1a7f51f8530f2a5073223c36b191b26cb3ba08d30970637fb382728762598c036b3d9a89695689c9f8c5b0fd56bc2857f31f752983fd47791";
        }
        // 70b838db5c82ad0e563e97c11f3bf8a0cadc9de9e4fdac24da2d60cd45ad00c19c65c2ecde01822d8c8c576e349ec21daf422672e6e759f74a2ac65241551bd233564d16146ee25e136cf8659c51454e1613e729767a9eb8cf2de2036ca33fa6e027c56f551e78096700e58c9e1404f5436e3d71a9175eb8e1a04f5a14815913756e3a000cfba9491d6f275176484dc284a2a6a0d3d085a5ea5a9d9df831833e0f8e5451d9108ccc79952cace5915b14192e8ab51173ae303feaaf11c5ed0d58161a48c77122d018d90db70e8da0e3f24f5b9c9780beb70786ed6f2f529c269db669adb88cecc59e9a14dd96c27f4581f968b32e9c792a5a67ecdb2c5269e48c
        // 0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730323938323137382c22657870223a313730333036383537382c226e6266223a313730323938323137382c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657231222c22617564223a22746573745f617564222c226e6f6e6365223a22307830313166616439346233336564666630303866393636633933633662616235336132343436383238623566303932343637303332336164306666303563336331227d0000010041a4b10600ca7472fb9691b140c4f45d9bb9be5ff2786664648a792ae6ef82f1d2eefc66aae89f5a3af46e8bc7cb8ee340c33f78239e50ce56e55346dc14f3137e54daf7a3b0122ca433bebbfe1e40903e7b0636826cc4eeccba38fc48d75386864503a0f0f5a854fd10632997bb93bfc81b420c60bb781d94eca5cdc4985b8e15533e7cc0dfdfec352623142cb317bc91d9f938ecea9dabb3f8a37f69836eaf33b8c3d800bbdce80f7a29a02dbf3c87bc09d34fb4c0fd07eb46830391a7b3c594290e3562510db1a7f51f8530f2a5073223c36b191b26cb3ba08d30970637fb382728762598c036b3d9a89695689c9f8c5b0fd56bc2857f31f752983fd47791
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

        vm.warp(1702983183);
        _recoveryModule.startRecovery(address(_account), 0, data, permissions);
    }
}
