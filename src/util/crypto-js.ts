import { Buffer } from 'buffer';
import CryptoJS from 'crypto-js';

// crypto-js uses WordArrays, need conversion functions... 
function byteArrayToWordArray(ba: Buffer | string) {
    if (typeof ba == 'string')
        return ba;

    var wa: any[] = [],
        i;
    for (i = 0; i < ba.length; i++) {
        wa[(i / 4) | 0] |= ba[i] << (24 - 8 * i);
    }

    return CryptoJS.lib.WordArray.create(wa, ba.length);
}

function wordArrayToByteArray(wordArrayObj: CryptoJS.lib.WordArray, length: number): number[] {
    var wordArray: number[];
    if (wordArrayObj.hasOwnProperty("sigBytes") && wordArrayObj.hasOwnProperty("words")) {
        length = wordArrayObj.sigBytes;
        wordArray = wordArrayObj.words;
    }
    else {
        wordArray = []
    }

    var result: number[] = [],
        bytes: number[],
        i = 0;
    while (length > 0) {
        bytes = wordToByteArray(wordArray[i], Math.min(4, length));
        length -= bytes.length;
        result.push(...bytes);
        i++;
    }
    return Array<number>().concat.apply([], result);
}

function wordToByteArray(word: number, length: number): number[] {
    var ba: number[] = [],
        xFF = 0xFF;
    if (length > 0)
        ba.push(word >>> 24);
    if (length > 1)
        ba.push((word >>> 16) & xFF);
    if (length > 2)
        ba.push((word >>> 8) & xFF);
    if (length > 3)
        ba.push(word & xFF);

    return ba;
}

// exports
export function sha256(data: Buffer): Buffer {
    return Buffer.from(wordArrayToByteArray(CryptoJS.SHA256(byteArrayToWordArray(data)), 32))
}

export function hash160(data: Buffer): Buffer {
    const d = sha256(data);
    return Buffer.from(wordArrayToByteArray(CryptoJS.RIPEMD160(byteArrayToWordArray(d)), 32));
}

export function hmacSha512(key: Buffer | string, data: Buffer): Buffer {
    var keyWord: CryptoJS.lib.WordArray | string;
    if (typeof key == 'string')
        keyWord = key
    else keyWord = byteArrayToWordArray(key)

    return Buffer.from(wordArrayToByteArray(CryptoJS.HmacSHA512(byteArrayToWordArray(data), keyWord), 32))
}

export function pbkdf2Sync(password: string | Buffer,
    salt: string | Buffer,
    iterations: number,
    keylen: number,
    digest: string
): Buffer {

    var passwordWord: CryptoJS.lib.WordArray | string;
    if (typeof password == 'string')
        passwordWord = password
    else passwordWord = byteArrayToWordArray(password)

    var saltWord: CryptoJS.lib.WordArray | string;
    if (typeof salt == 'string')
        saltWord = salt
    else saltWord = byteArrayToWordArray(salt)

    var hasher: any;
    switch (digest) {
        case "sha512":
            hasher = CryptoJS.algo.SHA512
            break;
        case "sha256":
            hasher = CryptoJS.algo.SHA256
            break;
        default:
            hasher = CryptoJS.algo.SHA1
    }
    var returnWord: CryptoJS.lib.WordArray = CryptoJS.PBKDF2(
        passwordWord,
        saltWord,
        { keySize: keylen / 4, iterations: iterations, hasher: hasher })

    return Buffer.from(wordArrayToByteArray(returnWord, 64))
}

export async function pbkdf2(password: string | Buffer,
    salt: string | Buffer,
    iterations: number,
    keylen: number,
    digest: string,
    callback: (err: Error | null, derivedKey: Buffer | null) => void
) {
    // no async version in crypto-js
    const buf: Buffer = pbkdf2Sync(password, salt, iterations, keylen, digest)
    callback(null, buf)
}

export default { sha256, hash160, hmacSha512, pbkdf2Sync, pbkdf2 };