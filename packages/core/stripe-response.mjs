// Shared bounded JSON decoding. Caller authenticates exact processor object
// identity and selects minimized fields; raw provider JSON must never be logged.
export async function readStripeJson(response) {
  if (
    !response?.headers?.get('content-type')?.startsWith('application/json') ||
    !response.body?.getReader
  )
    throw Error('Unexpected processor response.');
  const reader = response.body.getReader(),
    parts = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > 200000) {
        await reader.cancel();
        throw Error('Processor response exceeded its bound.');
      }
      parts.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}
