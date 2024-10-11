import * as zlib from 'zlib';

export function descompressGZIP(data: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    zlib.gunzip(data, (err, result) => {
      if (err) {
        reject(err);
      }
      resolve(result)
    });
  })
}
