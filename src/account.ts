// curve used to generate key/address
export enum CurveType{
    Ed25519 = 0,
    Secp25k1 = 1
}

export interface Account{
    // account address
    address:string,
    // path to get from seed to child node that produced this address
    fullpath:string,
    curve: CurveType,
    index:number
}