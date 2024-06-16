// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/RecoveryModule.sol";
import "../src/test/TestAccount.sol";
import "../src/TypesAndDecoders.sol";
import "../src/interfaces/IPermissionVerifier.sol";
import "../src/verifier/email/EmailVerifier.sol";

import "@safe-global/safe-contracts/contracts/Safe.sol";
import "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";

contract EmailSocialRecoveryTest is Test {
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
    EmailVerifier _verifier;

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
        _verifier = new EmailVerifier();
        _verifier.updateDKIMKey(
            keccak256(abi.encodePacked("s2023", "test.com")),
            hex"d33d118f811fa1bea72ded002cc0bc701e888f83793633f13da6983aff576b49fd792e9b3d79916efc54120b309667799732553508e15b1d53ee90655b5654e53c92c22d63d62f2c62deabe17155a0f48ae39b370813e3af8e46fa108a5f031625a6ec3abf2aca92c30936b9fab9357e46eaf5b837b21426c222247ce84d1be41cc6dd7a4eb7dbbd6989e8fed0144c500b2527e7e65e329ea3eca01827208ea0cbcde37f6679a4a55ace6d89ea1e9fa0bcd6a6284ab86fc2f1d08acd78a1b7dc8188955ecd0a64130f0ac7efff67bb28fff90a8de99e0778f736773787ea87117458b00259949dd5e0b869af597e83912d272829f3ecfe64ca9a6e040547bdfb"
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
        thresholdConfig0.threshold = uint64(_threshold);
        thresholdConfig0.lockPeriod = uint48(_lockPeriod);
        configArg.thresholdConfigs.push(thresholdConfig1);

        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(sha256("alice@test.com"));
            guardian.guardian = id;
            guardian.property = 1;
            configArg.guardianInfos.push(guardian);
        }
        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(sha256("bob@test.com"));
            guardian.guardian = id;
            guardian.property = 1;
            configArg.guardianInfos.push(guardian);
        }
        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(sha256("charlie@test.com"));
            guardian.guardian = id;
            guardian.property = 1;
            configArg.guardianInfos.push(guardian);
        }

        RecoveryConfigArg[] memory configArgs = new RecoveryConfigArg[](1);
        configArgs[0] = configArg;
        bytes32 configsHash = keccak256(abi.encode(configArgs));
        _recoveryModule.addConfigs(configsHash);

        vm.warp(block.timestamp + 3 days);
        _recoveryModule.executeConfigsUpdate(address(_account), configArgs);
        vm.stopPrank();

        console2.log("domainSeparator: ");
        console2.logBytes32(domainSeparator());
    }

    function testEmailInstantRecovery() public {
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
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[0].guardian.signer;
            permissions[0].guardian = id;
            permissions[0]
                .signature = hex"00000000150000005f0000000000000005000000120000009e000000ce000000d3000000c2000000ca0000014c66726f6d3a616c69636540746573742e636f6d0d0a7375626a6563743a3078363364666138376634613166326666663939633266356138613333653738666435656563643437336162653337393335623933326634396139313365353435310d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a5361742c203031204a756e20323032342031313a35383a3437202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313731373234333132373b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d00000100524a1e9d50618647f608a128acf14024b34139a010aa028dec21cf7d14ddf07550c673ac70e1c921a60e81b4526e5a49f45d84a7f2778bba2afb842108c19814930e4e20b4aa120de8acb021962eff8e141b240affc7ad2cd4f9ae616ca048146597da0e40c6302bdefa447fedfb5db4420395a7142a3724aaac36e7a4b98b672227f2321d70ee2f480e0535eac0ffa95cfabfb205ae5b311112f51ad70330103e5c00d44911b3706360dffb32cbbf8aff0a86224c8d7be4d8a03a06eceda3e5f17741298a8c82edb927bb001c41c0d53df2bfb2f7a62ff4cc802d987ad7ff873929d9de91c7de5771066bc5a603c74da6146ea0d962b5de97b4d6a243dd3c4e";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[1].guardian.signer;
            permissions[1].guardian = id;
            permissions[1]
                .signature = hex"00000000130000005d0000000000000005000000100000009c000000cc000000d1000000c0000000c80000014a66726f6d3a626f6240746573742e636f6d0d0a7375626a6563743a3078363364666138376634613166326666663939633266356138613333653738666435656563643437336162653337393335623933326634396139313365353435310d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a5361742c203031204a756e20323032342031323a30313a3036202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313731373234333236363b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d000001000b96a3327ad2d28979c150894e49f934292579f570bc7e0aeae36eb17d30cd17df7e0f0aa440e62da1a193edb510ca99cffdcc0bb44264c4c5872313b04cd6cd4ec15a9bb94bacaec918594f253aff3da7ac75325865d22966f5406a629d6f93a928ff74385a2bdb7106cc0d0ad42d4fb4c2f6428784cba6da156525f2b211431141225db90b0a019b40831a8fdab41b7d8ae2b5073c292fd5ba4bfd1a3758e989162f2a37cea9f7742d5466965cc84555e9217a2de01368b2911382c0caeb8499679cbdd6b08bd990327409e99306dc53fe43038dc320d33d6a06bbd9ff484b7b81d66e6d45b5616cd5f491e34c929b5986b1635ff677b8e658546b24238eb7";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[2].guardian.signer;
            permissions[2].guardian = id;
            permissions[2]
                .signature = hex"000000001700000061000000000000000500000014000000a0000000d0000000d5000000c4000000cc0000014e66726f6d3a636861726c696540746573742e636f6d0d0a7375626a6563743a3078363364666138376634613166326666663939633266356138613333653738666435656563643437336162653337393335623933326634396139313365353435310d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a5361742c203031204a756e20323032342031323a33353a3032202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313731373234353330323b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d000001009cea7dcde6d1b1cffb689b36e45c14b5a71495ca7ac5d9cf04ec4131d5461277f5a90094ff92bc8fd1d6dd6f4dca7f566e4a7bf0e459fa1f177607d394b0a96f060dceabe8300d19a02ceab2aa0316ed6aefbfb7b3097017cdce89743615eb45289438c80b015f25e3ab3131785131a67421243a01ffacfe0eb42479ed355514c215c8d93d4bdcf00871a359602156e2042404298f15f03c73bceff71458b122e019c19114650b3109b2d91ffee86373cdba954ddb6fbaccb4324d1c2f9dc89648a2d4954cdb9eea5be81d56985867b50a172c83c97fe44a4ed604298d4ca9ef8b41564b03b5097b4e8824371738263653d459a8e3b8f59d1487e53f5149574a";
        }

        vm.warp(1699582162);
        _recoveryModule.startRecovery(address(_account), 0, data, permissions);
    }
}
