export function encodeFrame(payload: Buffer): Buffer {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

export class FrameDecoder {
  private buf: Buffer = Buffer.alloc(0);

  push(chunk: Buffer): Buffer[] {
    this.buf = Buffer.concat([this.buf, chunk]);
    const frames: Buffer[] = [];
    for (;;) {
      if (this.buf.length < 4) break;
      const len = this.buf.readUInt32BE(0);
      if (len === 0 || len > 1024 * 1024) {
        throw new Error(`invalid frame length: ${len}`);
      }
      if (this.buf.length < 4 + len) break;
      frames.push(this.buf.subarray(4, 4 + len));
      this.buf = this.buf.subarray(4 + len);
    }
    return frames;
  }
}

