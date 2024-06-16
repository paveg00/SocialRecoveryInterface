/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumberish,
  BytesLike,
  FunctionFragment,
  Result,
  Interface,
  EventFragment,
  AddressLike,
  ContractRunner,
  ContractMethod,
  Listener,
} from "ethers";
import type {
  TypedContractEvent,
  TypedDeferredTopicFilter,
  TypedEventLog,
  TypedLogDescription,
  TypedListener,
  TypedContractMethod,
} from "../common";

export type IdentityStruct = {
  guardianVerifier: AddressLike;
  signer: BytesLike;
};

export type IdentityStructOutput = [
  guardianVerifier: string,
  signer: string
] & { guardianVerifier: string; signer: string };

export type PermissionStruct = {
  guardian: IdentityStruct;
  signature: BytesLike;
};

export type PermissionStructOutput = [
  guardian: IdentityStructOutput,
  signature: string
] & { guardian: IdentityStructOutput; signature: string };

export type GuardianInfoStruct = {
  guardian: IdentityStruct;
  property: BigNumberish;
};

export type GuardianInfoStructOutput = [
  guardian: IdentityStructOutput,
  property: bigint
] & { guardian: IdentityStructOutput; property: bigint };

export type ThresholdConfigStruct = {
  threshold: BigNumberish;
  lockPeriod: BigNumberish;
};

export type ThresholdConfigStructOutput = [
  threshold: bigint,
  lockPeriod: bigint
] & { threshold: bigint; lockPeriod: bigint };

export type RecoveryConfigArgStruct = {
  policyVerifier: AddressLike;
  guardianInfos: GuardianInfoStruct[];
  thresholdConfigs: ThresholdConfigStruct[];
};

export type RecoveryConfigArgStructOutput = [
  policyVerifier: string,
  guardianInfos: GuardianInfoStructOutput[],
  thresholdConfigs: ThresholdConfigStructOutput[]
] & {
  policyVerifier: string;
  guardianInfos: GuardianInfoStructOutput[];
  thresholdConfigs: ThresholdConfigStructOutput[];
};

export interface RecoveryModuleInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "NAME"
      | "VERSION"
      | "addConfigs"
      | "cancelRecovery"
      | "cancelRecoveryByGuardians"
      | "domainSeparator"
      | "executeConfigsUpdate"
      | "executeRecovery"
      | "getRecoveryConfigs"
      | "getRecoveryNonce"
      | "getRecoveryStatus"
      | "isGuardian"
      | "replaceConfigs"
      | "startRecovery"
      | "verifyPermissions"
      | "walletRecoveryNonce"
  ): FunctionFragment;

  getEvent(
    nameOrSignatureOrTopic:
      | "GuardiansUpdated"
      | "RecoveryCanceled"
      | "RecoveryExecuted"
      | "RecoveryStarted"
  ): EventFragment;

  encodeFunctionData(functionFragment: "NAME", values?: undefined): string;
  encodeFunctionData(functionFragment: "VERSION", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "addConfigs",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "cancelRecovery",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "cancelRecoveryByGuardians",
    values: [AddressLike, BigNumberish, PermissionStruct[]]
  ): string;
  encodeFunctionData(
    functionFragment: "domainSeparator",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "executeConfigsUpdate",
    values: [AddressLike, RecoveryConfigArgStruct[]]
  ): string;
  encodeFunctionData(
    functionFragment: "executeRecovery",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "getRecoveryConfigs",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "getRecoveryNonce",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "getRecoveryStatus",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "isGuardian",
    values: [AddressLike, IdentityStruct]
  ): string;
  encodeFunctionData(
    functionFragment: "replaceConfigs",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "startRecovery",
    values: [AddressLike, BigNumberish, BytesLike, PermissionStruct[]]
  ): string;
  encodeFunctionData(
    functionFragment: "verifyPermissions",
    values: [AddressLike, BigNumberish, BytesLike, PermissionStruct[]]
  ): string;
  encodeFunctionData(
    functionFragment: "walletRecoveryNonce",
    values: [AddressLike]
  ): string;

  decodeFunctionResult(functionFragment: "NAME", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "VERSION", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "addConfigs", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "cancelRecovery",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "cancelRecoveryByGuardians",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "domainSeparator",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "executeConfigsUpdate",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "executeRecovery",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "getRecoveryConfigs",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "getRecoveryNonce",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "getRecoveryStatus",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "isGuardian", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "replaceConfigs",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "startRecovery",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "verifyPermissions",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "walletRecoveryNonce",
    data: BytesLike
  ): Result;
}

export namespace GuardiansUpdatedEvent {
  export type InputTuple = [account: AddressLike];
  export type OutputTuple = [account: string];
  export interface OutputObject {
    account: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace RecoveryCanceledEvent {
  export type InputTuple = [account: AddressLike, nonce: BigNumberish];
  export type OutputTuple = [account: string, nonce: bigint];
  export interface OutputObject {
    account: string;
    nonce: bigint;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace RecoveryExecutedEvent {
  export type InputTuple = [
    account: AddressLike,
    newOwners: BytesLike,
    nonce: BigNumberish
  ];
  export type OutputTuple = [account: string, newOwners: string, nonce: bigint];
  export interface OutputObject {
    account: string;
    newOwners: string;
    nonce: bigint;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace RecoveryStartedEvent {
  export type InputTuple = [
    account: AddressLike,
    newOwners: BytesLike,
    nonce: BigNumberish,
    expireTime: BigNumberish
  ];
  export type OutputTuple = [
    account: string,
    newOwners: string,
    nonce: bigint,
    expireTime: bigint
  ];
  export interface OutputObject {
    account: string;
    newOwners: string;
    nonce: bigint;
    expireTime: bigint;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export interface RecoveryModule extends BaseContract {
  connect(runner?: ContractRunner | null): RecoveryModule;
  waitForDeployment(): Promise<this>;

  interface: RecoveryModuleInterface;

  queryFilter<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEventLog<TCEvent>>>;
  queryFilter<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEventLog<TCEvent>>>;

  on<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    listener: TypedListener<TCEvent>
  ): Promise<this>;
  on<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    listener: TypedListener<TCEvent>
  ): Promise<this>;

  once<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    listener: TypedListener<TCEvent>
  ): Promise<this>;
  once<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    listener: TypedListener<TCEvent>
  ): Promise<this>;

  listeners<TCEvent extends TypedContractEvent>(
    event: TCEvent
  ): Promise<Array<TypedListener<TCEvent>>>;
  listeners(eventName?: string): Promise<Array<Listener>>;
  removeAllListeners<TCEvent extends TypedContractEvent>(
    event?: TCEvent
  ): Promise<this>;

  NAME: TypedContractMethod<[], [string], "view">;

  VERSION: TypedContractMethod<[], [string], "view">;

  addConfigs: TypedContractMethod<
    [configsHash: BytesLike],
    [void],
    "nonpayable"
  >;

  cancelRecovery: TypedContractMethod<
    [account: AddressLike],
    [void],
    "nonpayable"
  >;

  cancelRecoveryByGuardians: TypedContractMethod<
    [
      account: AddressLike,
      configIndex: BigNumberish,
      permissions: PermissionStruct[]
    ],
    [void],
    "nonpayable"
  >;

  domainSeparator: TypedContractMethod<[], [string], "view">;

  executeConfigsUpdate: TypedContractMethod<
    [account: AddressLike, configArgs: RecoveryConfigArgStruct[]],
    [void],
    "nonpayable"
  >;

  executeRecovery: TypedContractMethod<
    [account: AddressLike],
    [void],
    "nonpayable"
  >;

  getRecoveryConfigs: TypedContractMethod<
    [account: AddressLike],
    [RecoveryConfigArgStructOutput[]],
    "view"
  >;

  getRecoveryNonce: TypedContractMethod<
    [account: AddressLike],
    [bigint],
    "view"
  >;

  getRecoveryStatus: TypedContractMethod<
    [account: AddressLike],
    [[boolean, bigint] & { isRecovering: boolean; expiryTime: bigint }],
    "view"
  >;

  isGuardian: TypedContractMethod<
    [account: AddressLike, guardian: IdentityStruct],
    [boolean],
    "view"
  >;

  replaceConfigs: TypedContractMethod<
    [configsHash: BytesLike],
    [void],
    "nonpayable"
  >;

  startRecovery: TypedContractMethod<
    [
      account: AddressLike,
      configIndex: BigNumberish,
      data: BytesLike,
      permissions: PermissionStruct[]
    ],
    [void],
    "nonpayable"
  >;

  verifyPermissions: TypedContractMethod<
    [
      account: AddressLike,
      configIndex: BigNumberish,
      digest: BytesLike,
      permissions: PermissionStruct[]
    ],
    [bigint],
    "nonpayable"
  >;

  walletRecoveryNonce: TypedContractMethod<
    [arg0: AddressLike],
    [bigint],
    "view"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "NAME"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "VERSION"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "addConfigs"
  ): TypedContractMethod<[configsHash: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "cancelRecovery"
  ): TypedContractMethod<[account: AddressLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "cancelRecoveryByGuardians"
  ): TypedContractMethod<
    [
      account: AddressLike,
      configIndex: BigNumberish,
      permissions: PermissionStruct[]
    ],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "domainSeparator"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "executeConfigsUpdate"
  ): TypedContractMethod<
    [account: AddressLike, configArgs: RecoveryConfigArgStruct[]],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "executeRecovery"
  ): TypedContractMethod<[account: AddressLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "getRecoveryConfigs"
  ): TypedContractMethod<
    [account: AddressLike],
    [RecoveryConfigArgStructOutput[]],
    "view"
  >;
  getFunction(
    nameOrSignature: "getRecoveryNonce"
  ): TypedContractMethod<[account: AddressLike], [bigint], "view">;
  getFunction(
    nameOrSignature: "getRecoveryStatus"
  ): TypedContractMethod<
    [account: AddressLike],
    [[boolean, bigint] & { isRecovering: boolean; expiryTime: bigint }],
    "view"
  >;
  getFunction(
    nameOrSignature: "isGuardian"
  ): TypedContractMethod<
    [account: AddressLike, guardian: IdentityStruct],
    [boolean],
    "view"
  >;
  getFunction(
    nameOrSignature: "replaceConfigs"
  ): TypedContractMethod<[configsHash: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "startRecovery"
  ): TypedContractMethod<
    [
      account: AddressLike,
      configIndex: BigNumberish,
      data: BytesLike,
      permissions: PermissionStruct[]
    ],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "verifyPermissions"
  ): TypedContractMethod<
    [
      account: AddressLike,
      configIndex: BigNumberish,
      digest: BytesLike,
      permissions: PermissionStruct[]
    ],
    [bigint],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "walletRecoveryNonce"
  ): TypedContractMethod<[arg0: AddressLike], [bigint], "view">;

  getEvent(
    key: "GuardiansUpdated"
  ): TypedContractEvent<
    GuardiansUpdatedEvent.InputTuple,
    GuardiansUpdatedEvent.OutputTuple,
    GuardiansUpdatedEvent.OutputObject
  >;
  getEvent(
    key: "RecoveryCanceled"
  ): TypedContractEvent<
    RecoveryCanceledEvent.InputTuple,
    RecoveryCanceledEvent.OutputTuple,
    RecoveryCanceledEvent.OutputObject
  >;
  getEvent(
    key: "RecoveryExecuted"
  ): TypedContractEvent<
    RecoveryExecutedEvent.InputTuple,
    RecoveryExecutedEvent.OutputTuple,
    RecoveryExecutedEvent.OutputObject
  >;
  getEvent(
    key: "RecoveryStarted"
  ): TypedContractEvent<
    RecoveryStartedEvent.InputTuple,
    RecoveryStartedEvent.OutputTuple,
    RecoveryStartedEvent.OutputObject
  >;

  filters: {
    "GuardiansUpdated(address)": TypedContractEvent<
      GuardiansUpdatedEvent.InputTuple,
      GuardiansUpdatedEvent.OutputTuple,
      GuardiansUpdatedEvent.OutputObject
    >;
    GuardiansUpdated: TypedContractEvent<
      GuardiansUpdatedEvent.InputTuple,
      GuardiansUpdatedEvent.OutputTuple,
      GuardiansUpdatedEvent.OutputObject
    >;

    "RecoveryCanceled(address,uint256)": TypedContractEvent<
      RecoveryCanceledEvent.InputTuple,
      RecoveryCanceledEvent.OutputTuple,
      RecoveryCanceledEvent.OutputObject
    >;
    RecoveryCanceled: TypedContractEvent<
      RecoveryCanceledEvent.InputTuple,
      RecoveryCanceledEvent.OutputTuple,
      RecoveryCanceledEvent.OutputObject
    >;

    "RecoveryExecuted(address,bytes,uint256)": TypedContractEvent<
      RecoveryExecutedEvent.InputTuple,
      RecoveryExecutedEvent.OutputTuple,
      RecoveryExecutedEvent.OutputObject
    >;
    RecoveryExecuted: TypedContractEvent<
      RecoveryExecutedEvent.InputTuple,
      RecoveryExecutedEvent.OutputTuple,
      RecoveryExecutedEvent.OutputObject
    >;

    "RecoveryStarted(address,bytes,uint256,uint48)": TypedContractEvent<
      RecoveryStartedEvent.InputTuple,
      RecoveryStartedEvent.OutputTuple,
      RecoveryStartedEvent.OutputObject
    >;
    RecoveryStarted: TypedContractEvent<
      RecoveryStartedEvent.InputTuple,
      RecoveryStartedEvent.OutputTuple,
      RecoveryStartedEvent.OutputObject
    >;
  };
}