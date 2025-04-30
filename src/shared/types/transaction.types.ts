export interface UnsignedTransaction {
  from: string,
  to: string,
  data: string,
  value: string,
  nonce: string,
  chainId: string,
  gasLimit: string,
  gasPrice: string
}

export interface RawTransactionWithSignature {
  raw: string,
  r: string,
  s: string,
  v: number
}

export interface EbsiSendTransactionResponse {
  jsonrpc: string,
  id: number,
  result: string
}

export interface EbsiTransaction {
  blockHash: string | null,
  blockNumber: string | null,
  chainId: string,
  from: string,
  gas: string,
  gasPrice: string,
  hash: string,
  input: string,
  nonce: string,
  to: string,
  transactionIndex: string | null,
  type: string,
  value: string,
  v: string,
  r: string,
  s: string
}
