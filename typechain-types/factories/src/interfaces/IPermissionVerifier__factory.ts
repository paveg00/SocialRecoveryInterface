/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Interface, type ContractRunner } from "ethers";
import type {
  IPermissionVerifier,
  IPermissionVerifierInterface,
} from "../../../src/interfaces/IPermissionVerifier";

const _abi = [
  {
    inputs: [],
    name: "getGuardianVerifierInfo",
    outputs: [
      {
        internalType: "bytes",
        name: "",
        type: "bytes",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "hash",
        type: "bytes32",
      },
      {
        internalType: "bytes",
        name: "signer",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "signature",
        type: "bytes",
      },
    ],
    name: "isValidPermission",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "hash",
        type: "bytes32",
      },
      {
        internalType: "bytes[]",
        name: "signers",
        type: "bytes[]",
      },
      {
        internalType: "bytes[]",
        name: "signatures",
        type: "bytes[]",
      },
    ],
    name: "isValidPermissions",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes[]",
        name: "signers",
        type: "bytes[]",
      },
    ],
    name: "isValidSigners",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

export class IPermissionVerifier__factory {
  static readonly abi = _abi;
  static createInterface(): IPermissionVerifierInterface {
    return new Interface(_abi) as IPermissionVerifierInterface;
  }
  static connect(
    address: string,
    runner?: ContractRunner | null
  ): IPermissionVerifier {
    return new Contract(
      address,
      _abi,
      runner
    ) as unknown as IPermissionVerifier;
  }
}