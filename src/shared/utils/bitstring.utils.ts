export function getBitFromBitString(data: Buffer, index: number) {
  const byte = Math.floor(index / 8);
  const bit = index % 8;
  const bitString = data[byte].toString(2).padStart(8, '0');
  return parseInt(bitString[bit]);
}
