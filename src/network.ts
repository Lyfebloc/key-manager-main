export enum NetworkFamily {
  // evm compatible blockchains
  EVM = 0,
  // solana compatible blockchains
  Solana = 1,
  // general tx. based networks like BTC, LTC, etc.
  Bitcoin = 2,
  // near compatible blockchains
  Near = 3,
  // COSMOS compatible blockchains
  Cosmos = 4,
  // ALGO compatible blockchains
  // standard derivation path: m/44'/283'/0'/0/0
  Algorand = 5,
}

export class NetworkInfo {
  public chainCode: number;
  public networkFamily: NetworkFamily;
  constructor(chainCode: number, networkFamily: NetworkFamily) {
    this.chainCode = chainCode;
    this.networkFamily = networkFamily;
  }
}

// SLIP-0044 specified coin types
export let NetworkInfoDict: { [name: string]: NetworkInfo } = {
  btc: new NetworkInfo(0, NetworkFamily.Bitcoin),
  ltc: new NetworkInfo(2, NetworkFamily.Bitcoin),
  doge: new NetworkInfo(3, NetworkFamily.Bitcoin),
  eth: new NetworkInfo(60, NetworkFamily.EVM),
  matic: new NetworkInfo(60, NetworkFamily.EVM),
  xmr: new NetworkInfo(128, NetworkFamily.Bitcoin),
  zec: new NetworkInfo(133, NetworkFamily.Bitcoin),
  bch: new NetworkInfo(145, NetworkFamily.Bitcoin),
  sol: new NetworkInfo(501, NetworkFamily.Solana),
  near: new NetworkInfo(397, NetworkFamily.Near),
  pokt: new NetworkInfo(635, NetworkFamily.EVM),
  bnb: new NetworkInfo(714, NetworkFamily.EVM),
  avaxc: new NetworkInfo(9005, NetworkFamily.EVM),
  one: new NetworkInfo(1023, NetworkFamily.Bitcoin),
  algo: new NetworkInfo(283, NetworkFamily.Algorand),
};

export interface INetwork {
  ticker: string;
  chainId: number;
}

export interface NetworkParameters {
  fullName: string;
  ticker: string;
  chainId?: number;
  networkFamilyName?: string;
}

export class Network {
  readonly fullName: string;
  readonly ticker: string;
  // path used for hdnode derivation
  readonly path: string;
  // base path without child node index
  readonly basePath: string;
  // BIP-44 coin code
  readonly chainId: number;
  readonly networkFamily: number;

  constructor(networkParams: NetworkParameters) {
    this.fullName = networkParams.fullName;
    this.ticker = networkParams.ticker.toLowerCase();
    this.chainId = networkParams.chainId
      ? networkParams.chainId
      : this.getChainId();
    this.networkFamily = networkParams.networkFamilyName
      ? NetworkFamilyFromFamilyName(networkParams.networkFamilyName)
      : this.getNetworkfamily();
    this.basePath = getBasePath(
      networkParams.ticker,
      networkParams.chainId,
      this.networkFamily
    );
    this.path = getFullPath(this.basePath, this.networkFamily);
  }

  // returns network family for given chain
  private getNetworkfamily(): number {
    let networkInfo: NetworkInfo = NetworkInfoDict[this.ticker];
    let networkFamily: NetworkFamily = NetworkFamily.EVM;
    if (networkInfo) {
      networkFamily = networkInfo.networkFamily;
    }
    return networkFamily;
  }

  // returns BIP-44 specified coin type (code)
  private getChainId(): number {
    let coinType: number = NetworkInfoDict[this.ticker].chainCode;
    return coinType;
  }
}

// default networks used to init. seed loop
export let defaultNetworks: { [name: string]: Network } = {};
defaultNetworks.algo = new Network({ fullName: "Algorand", ticker: "algo" });
defaultNetworks.eth = new Network({ fullName: "Ethereum", ticker: "eth" });
defaultNetworks.sol = new Network({ fullName: "Solana", ticker: "sol" });
defaultNetworks.avaxc = new Network({
  fullName: "Avalanche C Chain",
  ticker: "avaxc",
});
defaultNetworks.matic = new Network({ fullName: "Polygon", ticker: "matic" });
defaultNetworks.near = new Network({
  fullName: "Near Protocol",
  ticker: "near",
});

// return chain that matches ticker
export function NetworkFromTicker(ticker: string): Network {
  try {
    return defaultNetworks[ticker.toLowerCase()];
  } catch (err) {
    throw Error(`Unable to find network for ticker: ${ticker}`);
  }
}

//gets base path (full path minus account index)
export function getBasePath(
  ticker: string,
  chainCodeIn?: number,
  networkFamily?: NetworkFamily
): string {
  let chainCode: number;
  if (chainCodeIn) {
    chainCode = chainCodeIn;
  } else {
    let networkInfo: NetworkInfo = NetworkInfoDict[ticker];
    chainCode = networkInfo.chainCode;
  }
  let basePath = `m/44'/${chainCode}'/0'/0`;
  if (
    networkFamily &&
    (networkFamily == NetworkFamily.Solana ||
      NetworkFamily.Near ||
      NetworkFamily.Algorand)
  ) {
    switch (ticker.toLowerCase()) {
      case "near": {
        basePath = `m/44'/${chainCode}'`;
        break;
      }
      default: {
        basePath = `m/44'/${chainCode}'/0'`;
      }
    }
  }
  return basePath;
}

// builds coin path based on BIP-44 standard
// NOTE: standard full eth path is: m/44'/60'/0'/0
export function getFullPath(
  basePath: string,
  networkFamily?: NetworkFamily,
  depth = 0
): string {
  let path = basePath + `/${depth}`;
  // special cases for sol family networks WHICH USE DIFFERENT PATH DERIVATION SCHEMES
  if (
    networkFamily == NetworkFamily.Solana ||
    networkFamily == NetworkFamily.Near ||
    NetworkFamily.Algorand
  ) {
    path = basePath + `/${depth}'`;
  }
  return path;
}

export function NetworkFamilyFromFamilyName(familyName: string): NetworkFamily {
  switch (familyName.toLowerCase()) {
    case "bitcoin": {
      return NetworkFamily.EVM;
      break;
    }
    case "evm": {
      return NetworkFamily.EVM;
      break;
    }
    case "solana": {
      return NetworkFamily.Solana;
      break;
    }
    case "near": {
      return NetworkFamily.Near;
      break;
    }
    case "cosmos": {
      return NetworkFamily.Cosmos;
    }
    case "algorand": {
      return NetworkFamily.Algorand;
    }
    default: {
      // return evm network family as default
      return NetworkFamily.EVM;
      break;
    }
  }
}
