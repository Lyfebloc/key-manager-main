import { generateMnemonic, mnemonicToSeedSync } from "bip39";
import HDKey from "hdkey";
import { encode } from "bs58";
import { AES, enc } from "crypto-js";

import {
  Network,
  defaultNetworks,
  NetworkFromTicker,
  NetworkFamily,
  getBasePath,
} from "./network";
import { validateAndFormatMnemonic } from "./utils";
import {
  HDKeyring,
  KeyringOptions,
  SerializedHDKeyring,
  TransactionParameters,
  TypedDataParameters,
} from "./keyring";
import {
  COSMOS_FAMILY_KEYRING_NAME,
  EVM_FAMILY_KEYRING_NAME,
  NEAR_FAMILY_KEYRING_NAME,
  SOLANA_FAMILY_KEYRING_NAME,
} from "./constants";

export {
  normalizeHexAddress,
  normalizeMnemonic,
  validateAndFormatMnemonic,
  isValidEVMAddress,
  truncateAddress,
  formatAddress,
} from "./utils";

export {
  defaultNetworks,
  Network,
  NetworkFamily,
  NetworkParameters,
  NetworkFamilyFromFamilyName,
  NetworkFromTicker,
} from "./network";

export { Account, CurveType } from "./account";

export {
  HDKeyring,
  SerializedHDKeyring,
  KeyringOptions,
  defaultKeyringOptions,
  TransactionParameters,
  TypedDataParameters,
  EVMTypedData,
} from "./keyring";

export type Options = {
  strength?: number;
  path?: string;
  mnemonic?: string | null;
  mnemonicCipherText?: string | null;
  network?: Network;
  isCreation?: boolean;
  isLocked?: boolean;
  xpub?: string | null;
};

export const defaultOptions = {
  // default path is BIP-44, where depth 5 is the address index
  path: "m/44'/60'/0'/0",
  strength: 128,
  mnemonic: null,
  mnemonicCipherText: null,
  network: NetworkFromTicker("eth"),
  passphrase: null,
  isCreation: true,
  xpub: null,
  isLocked: false,
};

export interface SignedTransaction {
  evmFamilyTx?: string;
  solanaFamilyTx?: Uint8Array;
  nearFamilyTx?: Uint8Array;
  algorandFamilyTx?: Uint8Array;
}

export type SerializedSeedLoop = {
  version: number;
  mnemonic: string | null;
  mnemonicCipherText: string | null;
  // note: each key ring is SERIALIZED
  keyrings: SerializedHDKeyring[];
  id: string;
  xpub: string;
  isLocked: boolean;
};

export interface SeedLoop<T> {
  addAddresses(network: Network, n?: number): string[];
  getAddresses(network: Network): string[];
  addKeyRingByNetwork(network: Network): HDKeyring;
  networkOnSeedloop(network: Network): boolean;
  serialize(): T;
  addKeyRing(keyring: HDKeyring): void;
  keyringValid(keyring: HDKeyring): boolean;
  getKeyRing(network: Network): HDKeyring;
  signMessage(address: string, message: string, network: Network): string;
  lock(password: string): void;
  unlock(password: string): boolean;
  getIsLocked(): boolean;
  getSeedPhrase(): string | null;
  signTypedData(
    address: string,
    data: TypedDataParameters,
    network: Network
  ): Promise<string>;
}

export default class HDSeedLoop implements SeedLoop<SerializedSeedLoop> {
  readonly id: string;
  private networkToKeyring: { [name: string]: HDKeyring } = {};
  private hdKey: HDKey | null;
  public xpub: string;
  private mnemonic: string | null;
  private mnemonicCipherText: string | null = null;
  private isLocked: boolean = false;

  constructor(
    options: Options = {},
    networks: Network[] = Object.values(defaultNetworks)
  ) {
    const hdOptions: Required<Options> = {
      ...defaultOptions,
      ...options,
    };

    // usually runs when we deserialize a locked seedloop
    if (hdOptions.isLocked) {
      if (!hdOptions.xpub) {
        throw new Error(
          "Error: extended public key is missing. Needed when deserializing a locked seedloop."
        );
      }
      if (!hdOptions.mnemonicCipherText) {
        throw new Error(
          "Error: mnemonic ciphertext is missing. Needed when deserializing a locked seedloop."
        );
      }
      this.mnemonicCipherText = hdOptions.mnemonicCipherText;
      this.xpub = hdOptions.xpub;
      let newPubHdKey = HDKey.fromExtendedKey(this.xpub);
      this.id = encode(newPubHdKey.publicKey);
      this.isLocked = true;
      this.mnemonic = null;
      this.hdKey = null;
    } else {
      const mnemonic = validateAndFormatMnemonic(
        hdOptions.mnemonic || generateMnemonic(hdOptions.strength)
      );

      // if error occured when creating mnemonic
      if (!mnemonic) {
        throw new Error("Invalid mnemonic.");
      }

      this.mnemonic = mnemonic;

      this.hdKey = HDKey.fromMasterSeed(mnemonicToSeedSync(this.mnemonic));
      this.xpub = this.hdKey.publicExtendedKey;

      this.id = encode(this.hdKey.publicKey);

      // populate seedloop with keyrings
      this.populateLoopKeyrings(networks);
    }
  }

  // populate seed loop with keyrings for supported Networks
  private populateLoopKeyrings(
    networks: Network[] = Object.values(defaultNetworks)
  ) {
    if (!this.mnemonic || !this.hdKey) {
      throw Error(
        "Invalid keyring, ensure keyring was defined and added to seedloop."
      );
    }
    for (const Network of networks) {
      // if the network is already on the seedloop.. move on to the next network
      if (this.networkOnSeedloop(Network)) continue;
      // base hd path without child leaf
      let baseNetworkPath = getBasePath(
        Network.ticker,
        Network.chainId,
        Network.networkFamily
      );
      // evm cahins should all share the same path + address
      // based on eth path
      let networkToAdd = Network;
      if (Network.networkFamily == NetworkFamily.EVM) {
        let ethNetwork = NetworkFromTicker("eth");
        baseNetworkPath = getBasePath(
          ethNetwork.ticker,
          ethNetwork.chainId,
          ethNetwork.networkFamily
        );
        networkToAdd = ethNetwork;
      }
      // new hd key used for adding keyring
      let newHdKey = this.hdKey.derive(baseNetworkPath);
      let ringOptions: KeyringOptions = {
        // default path is BIP-44 ethereum coin type
        basePath: baseNetworkPath,
        network: networkToAdd,
        xpub: newHdKey.publicExtendedKey,
      };
      // create new key ring for Network given setup options
      var keyRing: HDKeyring = new HDKeyring(ringOptions);
      const seed = mnemonicToSeedSync(this.mnemonic);
      // add init addresses sync.
      keyRing.addAddresses(seed);
      // add key ring to seed loop
      this.addKeyRing(keyRing);
    }
  }

  networkOnSeedloop(network: Network): boolean {
    // account based families can share the same keyring
    // tx based families like bitcoin should have a distinct keyring for every network
    if (!network)
      throw new Error(
        "Error: network not provided. Unable to check if network is on seedloop."
      );
    switch (network.networkFamily) {
      case NetworkFamily.Bitcoin: {
        return network.ticker in this.networkToKeyring;
      }
      case NetworkFamily.EVM: {
        return EVM_FAMILY_KEYRING_NAME in this.networkToKeyring;
      }
      case NetworkFamily.Near: {
        return NEAR_FAMILY_KEYRING_NAME in this.networkToKeyring;
      }
      case NetworkFamily.Solana: {
        return SOLANA_FAMILY_KEYRING_NAME in this.networkToKeyring;
      }
      case NetworkFamily.Cosmos: {
        return COSMOS_FAMILY_KEYRING_NAME in this.networkToKeyring;
      }
      default: {
        return false;
      }
    }
  }

  // SERIALIZE SEEDLOOP
  serialize(): SerializedSeedLoop {
    let serializedKeyRings: SerializedHDKeyring[] = [];
    // serialize the key ring for every coin that's on the seed loop and add to serialized list output
    for (let ticker in this.networkToKeyring) {
      let keyring: HDKeyring = this.networkToKeyring[ticker];
      let serializedKeyRing: SerializedHDKeyring = keyring.serialize();
      serializedKeyRings.push(serializedKeyRing);
    }
    return {
      version: 1,
      mnemonic: this.mnemonic,
      keyrings: serializedKeyRings,
      id: this.id,
      xpub: this.xpub,
      mnemonicCipherText: this.mnemonicCipherText,
      isLocked: this.isLocked,
    };
  }

  static deserialize(obj: SerializedSeedLoop): HDSeedLoop {
    const {
      version,
      mnemonic,
      keyrings,
      id,
      isLocked,
      xpub,
      mnemonicCipherText,
    } = obj;
    if (version !== 1) {
      throw new Error(`Unknown serialization version ${obj.version}`);
    }
    // create loop options with pre-existing mnemonic
    // TODO add null check for mnemonic
    let loopOptions = {
      // default path is BIP-44 ethereum coin type, where depth 5 is the address index
      strength: 128,
      mnemonic: mnemonic,
      mnemonicCipherText: mnemonicCipherText,
      isCreation: false,
      isLocked: isLocked,
      xpub: xpub,
    };
    // create seed loop that will eventually be returned.
    var seedLoopNew: HDSeedLoop = new HDSeedLoop(loopOptions);
    // ensure HDnode matches original
    if (seedLoopNew.id != id)
      throw new Error(
        "The deserialized keyring fingerprint does not match the original."
      );
    // deserialize keyrings
    for (const sk of keyrings) {
      const keyRing: HDKeyring = HDKeyring.deserialize(sk);
      seedLoopNew.addKeyRing(keyRing);
    }
    return seedLoopNew;
  }

  // add keyring to dictionary and list of fellow key rings
  addKeyRing(keyring: HDKeyring) {
    let network: Network = keyring.network;
    switch (network.networkFamily) {
      case NetworkFamily.Bitcoin: {
        this.networkToKeyring[network.ticker] = keyring;
        break;
      }
      case NetworkFamily.EVM: {
        this.networkToKeyring[EVM_FAMILY_KEYRING_NAME] = keyring;
        keyring;
        break;
      }
      case NetworkFamily.Near: {
        this.networkToKeyring[NEAR_FAMILY_KEYRING_NAME] = keyring;
        break;
      }
      case NetworkFamily.Solana: {
        this.networkToKeyring[SOLANA_FAMILY_KEYRING_NAME] = keyring;
        break;
      }
      default: {
        this.networkToKeyring[network.ticker] = keyring;
        break;
      }
    }
  }

  addKeyRingByNetwork(network: Network): HDKeyring {
    // if keyring already available.. return it!
    if (this.networkOnSeedloop(network)) return this.getKeyRing(network);
    let networkPath = network.path;
    if (network.networkFamily == NetworkFamily.EVM) {
      networkPath = defaultOptions.path;
    }
    if (!this.mnemonic || !this.hdKey) {
      throw new Error(
        "Error: No mnemonic exists on this seedloop. Required to add a keyring."
      );
    }
    let baseNetworkPath = getBasePath(
      network.ticker,
      network.networkFamily,
      network.networkFamily
    );
    let newHdKey = this.hdKey.derive(baseNetworkPath);
    let ringOptions: KeyringOptions = {
      // default path is BIP-44 ethereum coin type
      basePath: baseNetworkPath,
      network: network,
      xpub: newHdKey.publicExtendedKey,
    };
    // create new key ring for Network given setup options
    var keyRing: HDKeyring = new HDKeyring(ringOptions);
    let seed = mnemonicToSeedSync(this.mnemonic);
    // add init addresses sync.
    keyRing.addAddresses(seed);
    // add key ring to seed loop
    this.addKeyRing(keyRing);
    return keyRing;
  }

  getAddresses(network: Network): string[] {
    let keyring = this.getKeyRing(network);
    if (!this.keyringValid(keyring))
      throw Error(
        "Invalid keyring, ensure keyring was defined and added to seedloop."
      );
    let addresses: string[] = keyring.getAddresses();
    return addresses;
  }

  addAddresses(network: Network, n?: number | undefined): string[] {
    // this error will throw if we have deserizlized a locked seedloop and try to add addresses
    // consumers can handle this error by casing om msg (checking for 'locked') and unlocking
    if (this.isLocked) {
      throw new Error(
        "Error: Seedloop is locked. Please unlock the seedloop, before adding addresses."
      );
    }
    if (!this.mnemonic) {
      throw new Error(
        "Error: No mnemonic exists on this seedloop. Required for address generation."
      );
    }
    let keyring = this.getKeyRing(network);
    if (!this.keyringValid(keyring))
      throw Error(
        "Invalid keyring, ensure keyring was defined and added to seedloop."
      );

    let seed = mnemonicToSeedSync(this.mnemonic);
    let addresses: string[] = keyring.addAddresses(seed, n);
    return addresses;
  }

  keyringValid(keyring: HDKeyring): boolean {
    return keyring != undefined;
  }

  getKeyRing(network: Network): HDKeyring {
    let keyringToReturn: HDKeyring;
    switch (network.networkFamily) {
      case NetworkFamily.Algorand: {
        keyringToReturn = this.networkToKeyring[network.ticker];
        break;
      }
      case NetworkFamily.Bitcoin: {
        keyringToReturn = this.networkToKeyring[network.ticker];
        break;
      }
      case NetworkFamily.EVM: {
        keyringToReturn = this.networkToKeyring[EVM_FAMILY_KEYRING_NAME];
        break;
      }
      case NetworkFamily.Near: {
        keyringToReturn = this.networkToKeyring[NEAR_FAMILY_KEYRING_NAME];
        break;
      }
      case NetworkFamily.Solana: {
        keyringToReturn = this.networkToKeyring[SOLANA_FAMILY_KEYRING_NAME];
        break;
      }
      default: {
        keyringToReturn = this.networkToKeyring[network.ticker];
        break;
      }
    }
    if (!keyringToReturn)
      throw new Error(
        `Error: Unable to retrieve keyring ${network.fullName}. Name not present in network map.`
      );
    return keyringToReturn;
  }

  signMessage(address: string, message: string, network: Network): string {
    if (this.isLocked) {
      throw new Error(
        "Error: Seedloop is locked. Please unlock the seedloop, before signing."
      );
    }
    if (!this.mnemonic) {
      throw new Error(
        "Error: No mnemonic exists on this seedloop. Required for signatures."
      );
    }
    let keyring = this.getKeyRing(network);
    let seed = mnemonicToSeedSync(this.mnemonic);
    let signedMsg = keyring.signMessage(seed, address, message);
    return signedMsg;
  }

  async signTypedData(
    address: string,
    data: TypedDataParameters,
    network: Network
  ): Promise<string> {
    if (this.isLocked) {
      throw new Error(
        "Error: Seedloop is locked. Please unlock the seedloop, before signing."
      );
    }
    if (!this.mnemonic) {
      throw new Error(
        "Error: No mnemonic exists on this seedloop. Required for signatures."
      );
    }
    let keyring = this.getKeyRing(network);
    let seed = mnemonicToSeedSync(this.mnemonic);
    let signedData = await keyring.signTypedData(seed, address, data);
    return signedData;
  }

  // routes transaction to correct signer
  async signTransaction(
    address: string,
    transaction: TransactionParameters,
    network = defaultNetworks.eth
  ): Promise<SignedTransaction> {
    if (this.isLocked) {
      throw new Error(
        "Error: Seedloop is locked. Please unlock the seedloop, before signing."
      );
    }
    if (!this.mnemonic) {
      throw new Error(
        "Error: No mnemonic exists on this seedloop. Required for address generation."
      );
    }
    let keyring = this.getKeyRing(network);
    let seed = mnemonicToSeedSync(this.mnemonic);
    let signedTransaction = await keyring.signTransaction(
      address,
      seed,
      transaction
    );
    return signedTransaction;
  }

  // encrypts unlocked wallet seed with a given password
  // replaces a password if it already exists
  addPassword(password: string) {
    if (this.isLocked) {
      throw new Error("Seedloop must be unlocked to add a password");
    }
    if (!this.mnemonic) {
      // something must be wrong if locking with mnemonic as null
      throw new Error(
        "Error: No mnemonic exists on this seedloop. Required to add password."
      );
    }
    const encryptedMnemonic = AES.encrypt(this.mnemonic, password).toString();
    this.mnemonicCipherText = encryptedMnemonic;
  }

  // checks if ciphertext exists on seedloop
  // returns true if so
  passwordExists(): boolean {
    return this.mnemonicCipherText != null;
  }

  // wipes all private keys from the seedloop. password must have been added first.
  lock() {
    if (!this.mnemonicCipherText) {
      throw new Error(
        "Error: No ciphertext exists on this seedloop. Make sure you have added a password first."
      );
    }
    this.isLocked = true;
    this.mnemonic = null;
    this.hdKey = null;
  }

  unlock(password: string): boolean {
    // if already unlocked, return true
    if (!this.isLocked) return true;
    let formattedMnemonic: string | null;
    if (!this.mnemonicCipherText) {
      // we need the ciphertext to decrypt
      throw new Error(
        "Error: No mnemonic ciphertext exists on this seedloop. P."
      );
    }
    try {
      const decryptedMnemonic = AES.decrypt(
        this.mnemonicCipherText,
        password
      ).toString(enc.Utf8);
      formattedMnemonic = validateAndFormatMnemonic(decryptedMnemonic);
    } catch (e) {
      /// unable to decrypt
      return false;
    }
    // not a valid mnemonic
    if (!formattedMnemonic) return false;
    // decryption worked! update state.
    this.mnemonic = formattedMnemonic;
    this.isLocked = false;
    return true;
  }

  // returns true if the seedloop is locked
  getIsLocked(): boolean {
    return this.isLocked;
  }

  // wrapper around mnemonic state, as mnemonic is a private variable
  getSeedPhrase(): string | null {
    return this.mnemonic;
  }
}
