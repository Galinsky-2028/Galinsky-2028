import { inflate, deflate } from "node:zlib";
import { promisify } from "node:util";
import { campaignFailure } from "./campaign-content.mjs";
const unzip = promisify(inflate),
  zip = promisify(deflate);
const SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
export const MAX_IMAGE_BYTES = 4 * 1024 * 1024;
export const MAX_IMAGE_PIXELS = 8000000;
let inFlight = 0;
const crcTable = Uint32Array.from({ length: 256 }, (_, n) => {
  for (let k = 0; k < 8; k++) n = n & 1 ? 0xedb88320 ^ (n >>> 1) : n >>> 1;
  return n >>> 0;
});
export function pngCrc(bytes) {
  let c = 0xffffffff;
  for (const b of bytes) c = crcTable[(c ^ b) & 255] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
export function pngChunk(type, data) {
  const chunk = Buffer.alloc(data.length + 12);
  chunk.writeUInt32BE(data.length);
  chunk.write(type, 4, 4, "ascii");
  data.copy(chunk, 8);
  chunk.writeUInt32BE(pngCrc(chunk.subarray(4, -4)), chunk.length - 4);
  return chunk;
}
const bad = () =>
  campaignFailure(
    "invalid_image",
    "Upload a static RGB or RGBA PNG produced by the image selector.",
  );
// Narrow, bounded PNG normalizer, not a general-purpose image decoder.
// Browser canvas converts other supported raster inputs to this format first.
// Reference: https://www.w3.org/TR/png-3/ (IHDR, IDAT, IEND, CRC and filters).
export async function normalizeCampaignPng(bytes) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length < 57 ||
    bytes.length > MAX_IMAGE_BYTES ||
    !bytes.subarray(0, 8).equals(SIGNATURE)
  )
    bad();
  if (inFlight >= 2)
    campaignFailure(
      "image_busy",
      "Image processing is busy. Retry shortly.",
      429,
    );
  inFlight++;
  try {
    let offset = 8,
      header = null,
      ended = false,
      seenIdat = false,
      idatEnded = false,
      chunks = 0;
    const compressed = [];
    while (offset < bytes.length) {
      if (++chunks > 512 || offset + 12 > bytes.length) bad();
      const size = bytes.readUInt32BE(offset),
        end = offset + 12 + size;
      if (size > MAX_IMAGE_BYTES || end > bytes.length) bad();
      const typeBytes = bytes.subarray(offset + 4, offset + 8),
        data = bytes.subarray(offset + 8, end - 4);
      // Node's ASCII decoder clears high bits. Validate the actual chunk bytes
      // before decoding, including the PNG reserved (third-letter) bit.
      if (
        !typeBytes.every(
          (b) => (b >= 65 && b <= 90) || (b >= 97 && b <= 122),
        ) ||
        typeBytes[2] < 65 ||
        typeBytes[2] > 90 ||
        pngCrc(bytes.subarray(offset + 4, end - 4)) !==
          bytes.readUInt32BE(end - 4)
      )
        bad();
      const type = typeBytes.toString("ascii");
      if (type === "IHDR") {
        if (header || offset !== 8 || size !== 13) bad();
        header = Buffer.from(data);
      } else if (!header) bad();
      else if (type === "IDAT") {
        if (ended || idatEnded) bad();
        seenIdat = true;
        compressed.push(data);
      } else if (type === "IEND") {
        if (size !== 0 || !seenIdat || end !== bytes.length) bad();
        ended = true;
      } else {
        if (
          type[0] === type[0].toUpperCase() ||
          ["acTL", "fcTL", "fdAT", "tRNS"].includes(type)
        )
          bad();
        if (seenIdat) idatEnded = true;
        // All ancillary data, including EXIF/text/profiles, is deliberately discarded.
      }
      offset = end;
    }
    if (!header || !ended) bad();
    const width = header.readUInt32BE(0),
      height = header.readUInt32BE(4),
      depth = header[8],
      type = header[9];
    if (
      !width ||
      !height ||
      width > 4096 ||
      height > 4096 ||
      width * height > MAX_IMAGE_PIXELS ||
      depth !== 8 ||
      ![2, 6].includes(type) ||
      header[10] !== 0 ||
      header[11] !== 0 ||
      header[12] !== 0
    )
      bad();
    const rowBytes = width * (type === 6 ? 4 : 3) + 1,
      expected = rowBytes * height,
      input = Buffer.concat(compressed);
    let decoded;
    try {
      decoded = await unzip(input, { maxOutputLength: expected, info: true });
    } catch {
      bad();
    }
    if (
      decoded.buffer.length !== expected ||
      decoded.engine.bytesWritten !== input.length
    )
      bad();
    for (let y = 0; y < height; y++)
      if (decoded.buffer[y * rowBytes] > 4) bad();
    let encoded;
    try {
      encoded = await zip(decoded.buffer, {
        level: 6,
        maxOutputLength: MAX_IMAGE_BYTES,
      });
    } catch {
      campaignFailure(
        "image_too_large",
        "The normalized image exceeds the media limit.",
        413,
      );
    }
    const normalized = Buffer.concat([
      SIGNATURE,
      pngChunk("IHDR", header),
      pngChunk("IDAT", encoded),
      pngChunk("IEND", Buffer.alloc(0)),
    ]);
    if (normalized.length > MAX_IMAGE_BYTES)
      campaignFailure(
        "image_too_large",
        "The normalized image exceeds the media limit.",
        413,
      );
    return { bytes: normalized, width, height };
  } finally {
    inFlight--;
  }
}
export function decodeCampaignUpload(value) {
  if (
    typeof value !== "string" ||
    value.length > Math.ceil(MAX_IMAGE_BYTES / 3) * 4 ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(value) ||
    value !== value.trim()
  )
    bad();
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) bad();
  return bytes;
}
