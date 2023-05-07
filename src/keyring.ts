import HDKey from "hdkey";
// ethers helpers
import { resolveProperties } from "@ethersproject/properties";
import { SigningKey } from "@ethersproject/signing-key";
import { serialize, UnsignedTransaction } from "@ethersproject/transactions";
import { TransactionRequest } from "@ethersproject/abstract-provider";
import { hashMessage } from "@ethersproject/hash";
import { publicToAddress } from "ethereumjs-util";
import { createEd25519SecretKey, normalizeHexAddress } from "./utils";
import { sign } from "tweetnacl";
import { SignedTransaction } from ".";
import { joinSignature } from "@ethersproject/bytes";
import { encode } from "bs58";
import { keccak256 } from "@ethersproject/keccak256";

import {
  getBasePath,
  getFullPath,
  Network,
  NetworkFamily,
  NetworkFromTicker,
} from "./network";
import { Account, CurveType } from "./account";
import { encodeAlgorandAdress } from "./encoding";
import { TypedDataEncoder } from "@ethersproject/hash/lib/typed-data";
import {
  TypedDataDomain,
  TypedDataField,
} from "@ethersproject/abstract-signer";

export type KeyringOptions = {
  basePath: string;
  network: Network;
  xpub: string;
};

export const defaultKeyringOptions: KeyringOptions = {
  // default basePath is BIP-44
  basePath: "m/44'/60'/0'/0",
  network: NetworkFromTicker("eth"),
  xpub: "",
};

export type SerializedHDKeyring = {
  basePath: string;
  keyringType: string;
  addressIndex: number;
  network: Network;
  xpub: string;
  accounts: Account[];
};

export interface TransactionParameters {
  evmTransaction?: TransactionRequest;
  transactionBuffer?: Uint8Array;
}

export interface TypedDataParameters {
  evmTypedData?: EVMTypedData;
}

export interface EVMTypedData {
  domain: TypedDataDomain;
  types: Record<string, Array<TypedDataField>>;
  value: Record<string, any>;
}

export interface Keyring<T> {
  serialize(): T;
  getAddresses(): string[];
  addAddresses(seed: Buffer, numNewAccounts?: number): string[];
  signMessage(
    seed: Buffer,
    fullpath: string,
    address: string,
    message: string
  ): string;
  signTransaction(
    address: string,
    seed: Buffer,
    txParams: TransactionParameters
  ): Promise<SignedTransaction>;
  signTypedData(
    seed: Buffer,
    address: string,
    data: TypedDataParameters
  ): Promise<string>;
}

export interface KeyringClass<T> {
  new (): Keyring<T>;
  deserialize(serializedKeyring: T): Promise<Keyring<T>>;
}

export class HDKeyring implements Keyring<SerializedHDKeyring> {
  static readonly type: string = "bip32";

  readonly basePath: string;

  readonly network: Network;

  private addressIndex: number;

  private accounts: Account[] = [];

  private readonly hdKey: HDKey;

  private readonly xpub: string;

  constructor(options: KeyringOptions) {
    const hdOptions: Required<KeyringOptions> = {
      ...options,
    };

    this.basePath = hdOptions.basePath;
    this.addressIndex = 0;
    this.accounts = [];
    this.network = hdOptions.network;
    // create hdkey from extended PUBLIC key so...
    // no sensitive keys stored on keyring
    this.hdKey = HDKey.fromExtendedKey(hdOptions.xpub);
    this.xpub = hdOptions.xpub;
  }

  serialize(): SerializedHDKeyring {
    return {
      accounts: this.accounts,
      keyringType: HDKeyring.type,
      basePath: this.basePath,
      addressIndex: this.addressIndex,
      network: this.network,
      xpub: this.xpub,
    };
  }

  static deserialize(obj: SerializedHDKeyring): HDKeyring {
    const { keyringType, basePath, addressIndex, network, xpub, accounts } =
      obj;

    if (keyringType !== HDKeyring.type) {
      throw new Error("HDKeyring only supports BIP-32/44 style HD wallets.");
    }

    if (addressIndex != accounts.length) {
      throw new Error(
        "Mismatch between accounts and account index when deserializing keyring."
      );
    }

    const keyring = new HDKeyring({
      basePath: basePath,
      xpub: xpub,
      network: network,
    });

    keyring.addRecoveredAccounts(accounts);

    return keyring;
  }

  getAddresses(): string[] {
    return this.accounts.map((account) => account.address);
  }

  // adds provided accounts to keyring if valid
  addRecoveredAccounts(accounts: Account[]) {
    // each account should be distinct
    // indices should ascend
    // order by ascending index
    accounts = accounts.sort((a, b) => a.index - b.index);
    let lastIndex: number = -1;
    for (const account of accounts) {
      if (account.index != lastIndex + 1) {
        throw new Error(
          "Error: Recovered account indices do not ascend by one."
        );
      }
      lastIndex = account.index;
    }
    this.accounts = accounts;
    this.addressIndex = accounts.length;
  }

  // we need seed for ED25519 Addys
  addAddresses(seed: Buffer, numNewAccounts = 1): string[] {
    const numAddresses = this.addressIndex;
    if (numNewAccounts < 0 || numAddresses + numNewAccounts > 2 ** 31 - 1) {
      throw new Error("New account index out of range");
    }
    for (let i = 0; i < numNewAccounts; i += 1) {
      let newAccount = this.generateAccount(numAddresses + i, seed);
      this.accounts.push(newAccount);
    }
    this.addressIndex += numNewAccounts;
    const addresses = this.getAddresses();
    return addresses.slice(-numNewAccounts);
  }

  signMessage(seed: Buffer, address: string, message: string): string {
    let account: Account | undefined = this.accounts.find(
      (a) => a.address.toLowerCase() == address.toLowerCase()
    );
    if (!account)
      throw new Error(
        "Error: Unable to find an account that matches the given address"
      );
    let signedMsg: string;
    switch (this.network.networkFamily) {
      // TODO: UPDATE TO PROVIDE SUPPORT FOR NON-EVM MESSAGES
      case NetworkFamily.EVM: {
        signedMsg = this.signEVMMessage(seed, account, message);
        break;
      }
      default: {
        throw Error(
          `Error: ${this.network.fullName} message signatures not yet implemented.`
        );
      }
    }
    return signedMsg;
  }

  async signTypedData(
    seed: Buffer,
    address: string,
    data: TypedDataParameters
  ): Promise<string> {
    let account: Account | undefined = this.accounts.find(
      (a) => a.address.toLowerCase() == address.toLowerCase()
    );
    if (!account)
      throw new Error(
        "Error: Unable to find an account that matches the given address"
      );
    let signedMsg: string;
    switch (this.network.networkFamily) {
      // TODO: UPDATE TO PROVIDE SUPPORT FOR NON-EVM MESSAGES
      case NetworkFamily.EVM: {
        if (!data.evmTypedData) {
          throw new Error("Error: EVM typed data not provided.");
        }
        signedMsg = await this.signEVMTypedData(
          seed,
          account,
          data.evmTypedData
        );
        break;
      }
      default: {
        throw Error(
          `Error: ${this.network.fullName} message signatures not yet implemented.`
        );
      }
    }
    return signedMsg;
  }

  private async signEVMTypedData(
    seed: Buffer,
    account: Account,
    evmTypedData: EVMTypedData
  ): Promise<string> {
    const { domain, types, value } = evmTypedData;
    let newHDKey = HDKey.fromMasterSeed(seed);
    let ethNetwork = NetworkFromTicker("eth");
    const baseNetworkPath = getBasePath(
      ethNetwork.ticker,
      ethNetwork.chainId,
      ethNetwork.networkFamily
    );
    newHDKey = newHDKey.derive(baseNetworkPath);
    newHDKey = newHDKey.derive("m/" + account.index);
    let signingKey: SigningKey = new SigningKey(newHDKey.privateKey);
    // resolve names
    // sign populated data
    const populated = await TypedDataEncoder.resolveNames(
      domain,
      types,
      value,
      async (name: string) => {
        // TODO: consider ens resolution
        return name;
      }
    );
    const dataToSign: string = TypedDataEncoder.hash(
      populated.domain,
      types,
      populated.value
    );
    const signature: string = joinSignature(signingKey.signDigest(dataToSign));
    return signature;
  }

  private signEVMMessage(
    seed: Buffer,
    account: Account,
    message: string
  ): string {
    let newHDKey = HDKey.fromMasterSeed(seed);
    let ethNetwork = NetworkFromTicker("eth");
    const baseNetworkPath = getBasePath(
      ethNetwork.ticker,
      ethNetwork.chainId,
      ethNetwork.networkFamily
    );
    newHDKey = newHDKey.derive(baseNetworkPath);
    newHDKey = newHDKey.derive("m/" + account.index);
    let signingKey: SigningKey = new SigningKey(newHDKey.privateKey);
    const signature = joinSignature(
      signingKey.signDigest(hashMessage(message))
    );
    return signature;
  }

  // currently unused
  // private async signEd25519Message(seed:Buffer, account:Account, message:string):Promise<string>{
  //     var msg = Buffer.from(message);
  //     let signedMsg = await this.signSolMessage(seed, account, msg);
  //     return signedMsg.toString();
  // }

  generateAccount(index: number, seed: Buffer): Account {
    // derive child pub key
    switch (this.network.networkFamily) {
      case NetworkFamily.EVM: {
        // use default address created by ethers wallet
        return this.generateEVMAccount(index);
      }
      case NetworkFamily.Solana: {
        return this.generateED25519Address(seed, index);
      }
      case NetworkFamily.Near: {
        // generate ed25519Address as hex
        return this.generateED25519Address(seed, index, true);
      }
      case NetworkFamily.Algorand: {
        return this.generateAlgorandAccount(seed, index);
      }
      default: {
        throw Error(`Unable to generate address for: ${this.network.fullName}`);
      }
    }
  }

  private generateAlgorandAccount(
    seed: Buffer,
    accountNumber: number
  ): Account {
    let newHDKey = HDKey.fromMasterSeed(seed);
    let accountPath = getFullPath(
      this.basePath,
      this.network.networkFamily,
      accountNumber
    );
    newHDKey = newHDKey.derive(accountPath);
    // get hd derived ed25519 curve seed
    let hdED25519Seed: Buffer = createEd25519SecretKey(accountPath, seed);
    let keypair: nacl.SignKeyPair = sign.keyPair.fromSeed(hdED25519Seed);
    const newAddress: string = encodeAlgorandAdress(keypair.publicKey);
    let newAccount: Account = {
      address: newAddress,
      fullpath: accountPath,
      curve: CurveType.Ed25519,
      index: accountNumber,
    };
    return newAccount;
  }

  private generateEVMAccount(accountNumber: number): Account {
    // remember... we already derived hd key parents with basepath
    let accountPubkey = this.hdKey.derive("m/" + accountNumber).publicKey;
    let addressBuffer = publicToAddress(accountPubkey, true);
    // Only take the lower 160bits of the hash
    let newAddress: string = "0x" + addressBuffer.toString("hex");
    newAddress = normalizeHexAddress(newAddress);
    let accountPath = getFullPath(
      this.basePath,
      this.network.networkFamily,
      accountNumber
    );
    let newAccount: Account = {
      address: newAddress,
      fullpath: accountPath,
      curve: CurveType.Secp25k1,
      index: accountNumber,
    };
    return newAccount;
  }

  private generateED25519Address(
    seed: Buffer,
    accountNumber: number,
    isHexRep?: boolean
  ): Account {
    let newHDKey = HDKey.fromMasterSeed(seed);
    let accountPath = getFullPath(
      this.basePath,
      this.network.networkFamily,
      accountNumber
    );
    newHDKey = newHDKey.derive(accountPath);
    // get hd derived ed25519 curve seed
    let hdED25519Seed: Buffer = createEd25519SecretKey(accountPath, seed);
    let keypair: nacl.SignKeyPair = sign.keyPair.fromSeed(hdED25519Seed);
    let newAddress: string;
    if (isHexRep) {
      newAddress = Buffer.from(keypair.publicKey).toString("hex");
    } else {
      newAddress = encode(keypair.publicKey);
    }
    let newAccount: Account = {
      address: newAddress,
      fullpath: accountPath,
      curve: CurveType.Secp25k1,
      index: accountNumber,
    };
    return newAccount;
  }

  // SIGNING METHODS
  async signTransaction(
    address: string,
    seed: Buffer,
    txParams: TransactionParameters
  ): Promise<SignedTransaction> {
    let account: Account | undefined = this.accounts.find(
      (a) => a.address.toLowerCase() == address.toLowerCase()
    );
    if (!account)
      throw new Error(
        "Error: Unable to find an account that matches the given address"
      );
    let signedTx: SignedTransaction = {};
    switch (this.network.networkFamily) {
      case NetworkFamily.Algorand: {
        // ensure sol tx. was passed in
        if (!txParams.transactionBuffer)
          throw Error("Algorand transaction not provided.");
        signedTx.algorandFamilyTx = await this.signAlgorandMessage(
          seed,
          account,
          txParams.transactionBuffer
        );
        return signedTx;
      }
      case NetworkFamily.EVM: {
        // ensure evm tx. was passed in
        if (!txParams.evmTransaction)
          throw Error("EVM transaction not provided.");
        // use default signer implemented by ethers wallet
        signedTx.evmFamilyTx = await this.signEVMTransaction(
          seed,
          account,
          txParams.evmTransaction
        );
        return signedTx;
      }
      case NetworkFamily.Solana: {
        // ensure sol tx. was passed in
        if (!txParams.transactionBuffer)
          throw Error("Sol transaction not provided.");
        signedTx.solanaFamilyTx = await this.signSolMessage(
          seed,
          account,
          txParams.transactionBuffer
        );
        return signedTx;
      }
      case NetworkFamily.Near: {
        // ensure near tx. was passed in
        if (!txParams.transactionBuffer)
          throw Error("NEAR transaction not provided.");
        // solana and near families can use same signature method
        signedTx.nearFamilyTx = await this.signSolMessage(
          seed,
          account,
          txParams.transactionBuffer
        );
        return signedTx;
      }
      default: {
        throw Error(
          `Error: ${this.network.fullName} signatures not yet supported.`
        );
      }
    }
  }

  private async signAlgorandMessage(
    seed: Buffer,
    account: Account,
    msg: Uint8Array
  ) {
    // get hd derived ed25519 curve seed
    let hdED25519Seed: Buffer = createEd25519SecretKey(account.fullpath, seed);
    let keypair: nacl.SignKeyPair = sign.keyPair.fromSeed(hdED25519Seed);
    const signature = sign.detached(msg, keypair.secretKey);
    return Buffer.from(signature);
  }

  private async signEVMTransaction(
    seed: Buffer,
    account: Account,
    transaction: TransactionRequest
  ): Promise<string> {
    let newHDKey = HDKey.fromMasterSeed(seed);
    let ethNetwork = NetworkFromTicker("eth");
    const baseNetworkPath = getBasePath(
      ethNetwork.ticker,
      ethNetwork.chainId,
      ethNetwork.networkFamily
    );
    newHDKey = newHDKey.derive(baseNetworkPath);
    newHDKey = newHDKey.derive("m/" + account.index);
    let signingKey: SigningKey = new SigningKey(newHDKey.privateKey);
    if (!SigningKey.isSigningKey(signingKey)) {
      throw new Error(
        "Error: Unable to create EVM signing key from hd private key."
      );
    }

    let txResolved: TransactionRequest = {};
    // try to resolve properties... fall back to input tx if resolution fails
    try {
      txResolved = await resolveProperties(transaction);
    } catch (e) {
      txResolved = transaction;
    }
    // remove from address from object
    delete txResolved.from;

    const txDigest = keccak256(serialize(<UnsignedTransaction>txResolved));
    const sigObject = signingKey.signDigest(txDigest);
    const signedTx = serialize(<UnsignedTransaction>txResolved, sigObject);
    return signedTx;
  }

  // can sign data OR transaction!
  private async signSolMessage(
    seed: Buffer,
    account: Account,
    solTransactionBuffer: Uint8Array
  ): Promise<Uint8Array> {
    // get hd derived ed25519 curve seed
    let hdED25519Seed: Buffer = createEd25519SecretKey(account.fullpath, seed);
    let keypair: nacl.SignKeyPair = sign.keyPair.fromSeed(hdED25519Seed);
    // create sol signature
    let solSignature: Uint8Array = sign.detached(
      solTransactionBuffer,
      keypair.secretKey
    );
    return solSignature;
  }
}
