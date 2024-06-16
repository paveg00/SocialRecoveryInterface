/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
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
} from "../../../common";

export interface AudManagerInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "addOpenIDAudience"
      | "deleteOpenIDAudience"
      | "isAudienceValid"
      | "owner"
      | "renounceOwnership"
      | "transferOwnership"
  ): FunctionFragment;

  getEvent(
    nameOrSignatureOrTopic:
      | "AddOpenIDAudience"
      | "DeleteOpenIDAudience"
      | "OwnershipTransferred"
  ): EventFragment;

  encodeFunctionData(
    functionFragment: "addOpenIDAudience",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "deleteOpenIDAudience",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "isAudienceValid",
    values: [BytesLike]
  ): string;
  encodeFunctionData(functionFragment: "owner", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "renounceOwnership",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "transferOwnership",
    values: [AddressLike]
  ): string;

  decodeFunctionResult(
    functionFragment: "addOpenIDAudience",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "deleteOpenIDAudience",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "isAudienceValid",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "owner", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "renounceOwnership",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "transferOwnership",
    data: BytesLike
  ): Result;
}

export namespace AddOpenIDAudienceEvent {
  export type InputTuple = [_key: BytesLike];
  export type OutputTuple = [_key: string];
  export interface OutputObject {
    _key: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace DeleteOpenIDAudienceEvent {
  export type InputTuple = [_key: BytesLike];
  export type OutputTuple = [_key: string];
  export interface OutputObject {
    _key: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace OwnershipTransferredEvent {
  export type InputTuple = [previousOwner: AddressLike, newOwner: AddressLike];
  export type OutputTuple = [previousOwner: string, newOwner: string];
  export interface OutputObject {
    previousOwner: string;
    newOwner: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export interface AudManager extends BaseContract {
  connect(runner?: ContractRunner | null): AudManager;
  waitForDeployment(): Promise<this>;

  interface: AudManagerInterface;

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

  addOpenIDAudience: TypedContractMethod<
    [_key: BytesLike],
    [void],
    "nonpayable"
  >;

  deleteOpenIDAudience: TypedContractMethod<
    [_key: BytesLike],
    [void],
    "nonpayable"
  >;

  isAudienceValid: TypedContractMethod<[_key: BytesLike], [boolean], "view">;

  owner: TypedContractMethod<[], [string], "view">;

  renounceOwnership: TypedContractMethod<[], [void], "nonpayable">;

  transferOwnership: TypedContractMethod<
    [newOwner: AddressLike],
    [void],
    "nonpayable"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "addOpenIDAudience"
  ): TypedContractMethod<[_key: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "deleteOpenIDAudience"
  ): TypedContractMethod<[_key: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "isAudienceValid"
  ): TypedContractMethod<[_key: BytesLike], [boolean], "view">;
  getFunction(
    nameOrSignature: "owner"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "renounceOwnership"
  ): TypedContractMethod<[], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "transferOwnership"
  ): TypedContractMethod<[newOwner: AddressLike], [void], "nonpayable">;

  getEvent(
    key: "AddOpenIDAudience"
  ): TypedContractEvent<
    AddOpenIDAudienceEvent.InputTuple,
    AddOpenIDAudienceEvent.OutputTuple,
    AddOpenIDAudienceEvent.OutputObject
  >;
  getEvent(
    key: "DeleteOpenIDAudience"
  ): TypedContractEvent<
    DeleteOpenIDAudienceEvent.InputTuple,
    DeleteOpenIDAudienceEvent.OutputTuple,
    DeleteOpenIDAudienceEvent.OutputObject
  >;
  getEvent(
    key: "OwnershipTransferred"
  ): TypedContractEvent<
    OwnershipTransferredEvent.InputTuple,
    OwnershipTransferredEvent.OutputTuple,
    OwnershipTransferredEvent.OutputObject
  >;

  filters: {
    "AddOpenIDAudience(bytes32)": TypedContractEvent<
      AddOpenIDAudienceEvent.InputTuple,
      AddOpenIDAudienceEvent.OutputTuple,
      AddOpenIDAudienceEvent.OutputObject
    >;
    AddOpenIDAudience: TypedContractEvent<
      AddOpenIDAudienceEvent.InputTuple,
      AddOpenIDAudienceEvent.OutputTuple,
      AddOpenIDAudienceEvent.OutputObject
    >;

    "DeleteOpenIDAudience(bytes32)": TypedContractEvent<
      DeleteOpenIDAudienceEvent.InputTuple,
      DeleteOpenIDAudienceEvent.OutputTuple,
      DeleteOpenIDAudienceEvent.OutputObject
    >;
    DeleteOpenIDAudience: TypedContractEvent<
      DeleteOpenIDAudienceEvent.InputTuple,
      DeleteOpenIDAudienceEvent.OutputTuple,
      DeleteOpenIDAudienceEvent.OutputObject
    >;

    "OwnershipTransferred(address,address)": TypedContractEvent<
      OwnershipTransferredEvent.InputTuple,
      OwnershipTransferredEvent.OutputTuple,
      OwnershipTransferredEvent.OutputObject
    >;
    OwnershipTransferred: TypedContractEvent<
      OwnershipTransferredEvent.InputTuple,
      OwnershipTransferredEvent.OutputTuple,
      OwnershipTransferredEvent.OutputObject
    >;
  };
}