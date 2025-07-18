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
  AddressLike,
  ContractRunner,
  ContractMethod,
  Listener,
} from "ethers";
import type {
  TypedContractEvent,
  TypedDeferredTopicFilter,
  TypedEventLog,
  TypedListener,
  TypedContractMethod,
} from "./common";

export interface Algo3SimpleEncryptionInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "check_if_registered"
      | "get_file_owner_dpcn_address"
      | "get_file_share_result"
      | "get_pending_share_requests"
      | "get_users_pending_registration"
      | "request_file_share"
      | "request_registration"
      | "respond_with_client_encrypted_sym_key"
      | "respond_with_registration"
      | "upload_file"
  ): FunctionFragment;

  encodeFunctionData(
    functionFragment: "check_if_registered",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "get_file_owner_dpcn_address",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "get_file_share_result",
    values: [AddressLike, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "get_pending_share_requests",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "get_users_pending_registration",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "request_file_share",
    values: [AddressLike, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "request_registration",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "respond_with_client_encrypted_sym_key",
    values: [AddressLike, BigNumberish, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "respond_with_registration",
    values: [AddressLike, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "upload_file",
    values: [
      AddressLike,
      BigNumberish,
      string,
      string,
      BigNumberish,
      BigNumberish
    ]
  ): string;

  decodeFunctionResult(
    functionFragment: "check_if_registered",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "get_file_owner_dpcn_address",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "get_file_share_result",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "get_pending_share_requests",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "get_users_pending_registration",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "request_file_share",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "request_registration",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "respond_with_client_encrypted_sym_key",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "respond_with_registration",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "upload_file",
    data: BytesLike
  ): Result;
}

export interface Algo3SimpleEncryption extends BaseContract {
  connect(runner?: ContractRunner | null): Algo3SimpleEncryption;
  waitForDeployment(): Promise<this>;

  interface: Algo3SimpleEncryptionInterface;

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

  check_if_registered: TypedContractMethod<
    [user: AddressLike],
    [boolean],
    "view"
  >;

  get_file_owner_dpcn_address: TypedContractMethod<
    [user: AddressLike],
    [bigint],
    "view"
  >;

  get_file_share_result: TypedContractMethod<
    [client: AddressLike, file_id: BigNumberish],
    [[boolean, bigint] & { client_accessible_sym_key: bigint }],
    "view"
  >;

  get_pending_share_requests: TypedContractMethod<
    [],
    [[string[], bigint[]]],
    "view"
  >;

  get_users_pending_registration: TypedContractMethod<[], [string[]], "view">;

  request_file_share: TypedContractMethod<
    [client: AddressLike, file_id: BigNumberish],
    [void],
    "nonpayable"
  >;

  request_registration: TypedContractMethod<
    [user: AddressLike],
    [void],
    "nonpayable"
  >;

  respond_with_client_encrypted_sym_key: TypedContractMethod<
    [
      client: AddressLike,
      file_id: BigNumberish,
      client_accessible_sym_key: BigNumberish
    ],
    [void],
    "nonpayable"
  >;

  respond_with_registration: TypedContractMethod<
    [user: AddressLike, dpcn_pk: BigNumberish],
    [void],
    "nonpayable"
  >;

  upload_file: TypedContractMethod<
    [
      owner: AddressLike,
      file_id: BigNumberish,
      file_info: string,
      file_address: string,
      owner_accessible_sym_key: BigNumberish,
      dpcn_accessible_sym_key: BigNumberish
    ],
    [void],
    "nonpayable"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "check_if_registered"
  ): TypedContractMethod<[user: AddressLike], [boolean], "view">;
  getFunction(
    nameOrSignature: "get_file_owner_dpcn_address"
  ): TypedContractMethod<[user: AddressLike], [bigint], "view">;
  getFunction(
    nameOrSignature: "get_file_share_result"
  ): TypedContractMethod<
    [client: AddressLike, file_id: BigNumberish],
    [[boolean, bigint] & { client_accessible_sym_key: bigint }],
    "view"
  >;
  getFunction(
    nameOrSignature: "get_pending_share_requests"
  ): TypedContractMethod<[], [[string[], bigint[]]], "view">;
  getFunction(
    nameOrSignature: "get_users_pending_registration"
  ): TypedContractMethod<[], [string[]], "view">;
  getFunction(
    nameOrSignature: "request_file_share"
  ): TypedContractMethod<
    [client: AddressLike, file_id: BigNumberish],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "request_registration"
  ): TypedContractMethod<[user: AddressLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "respond_with_client_encrypted_sym_key"
  ): TypedContractMethod<
    [
      client: AddressLike,
      file_id: BigNumberish,
      client_accessible_sym_key: BigNumberish
    ],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "respond_with_registration"
  ): TypedContractMethod<
    [user: AddressLike, dpcn_pk: BigNumberish],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "upload_file"
  ): TypedContractMethod<
    [
      owner: AddressLike,
      file_id: BigNumberish,
      file_info: string,
      file_address: string,
      owner_accessible_sym_key: BigNumberish,
      dpcn_accessible_sym_key: BigNumberish
    ],
    [void],
    "nonpayable"
  >;

  filters: {};
}
