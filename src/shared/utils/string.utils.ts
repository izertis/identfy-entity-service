export function stringToHex(data: string) {
  let result = '';
  for (let index = 0; index < data.length; index++) {
    const hex = data.charCodeAt(index).toString(16);
    result += hex.length === 1 ? '0' + hex : hex;
  }
  return '0x' + result;
}
