// Framing test for the page's parseFeed(), run WITHOUT a browser.
//
// The page's video arrives as <Q tid><Q publish-ms><I length> + JPEG on one
// socket, parsed by parseFeed() in the served <script>.  There is no browser on
// this machine, so this pulls that exact function out of the page and runs it
// against synthetic streams: split at every awkward chunk boundary, with a
// truncated frame, an empty read, and a corrupt length to check the resync.
//
// usage: node feedtest.js [page.js]
//   page.js = the served <script> body; if omitted it is obtained from
//             server.py's PAGE via python3.
'use strict';
const fs = require('fs');
const {execFileSync} = require('child_process');

function servedJs() {
  if (process.argv[2]) return fs.readFileSync(process.argv[2], 'utf8');
  const py = [
    'import re, sys',
    "sys.path.insert(0, 'wyze-cam-stream')",
    'import server',
    "sys.stdout.write(re.search(r'<script>\\n(.*?)\\n</script>',"
      + ' server.PAGE, re.S).group(1))',
  ].join('; ');
  return execFileSync('python3', ['-c', py], {encoding: 'utf8', cwd: __dirname});
}

const src = servedJs();
const m = src.match(/function parseFeed\(buf\) \{[\s\S]*?\n\}/);
if (!m) {
  console.error('FAIL: parseFeed() not found in the served page');
  process.exit(1);
}
const FEED_HDR = 20;
const parseFeed = eval('(' + m[0] + ')');   // the shipped function, verbatim

// ---- helpers -------------------------------------------------------------
let fails = 0;
function check(name, ok, extra) {
  console.log('  %s %s%s', ok ? 'ok  ' : 'FAIL', name, extra ? '  ' + extra : '');
  if (!ok) fails++;
}

function jpeg(n, seed) {                    // plausible JPEG-shaped payload
  const b = new Uint8Array(n);
  b[0] = 0xff; b[1] = 0xd8;
  for (let i = 2; i < n - 2; i++) b[i] = (i * 31 + seed) & 0xff;
  b[n - 2] = 0xff; b[n - 1] = 0xd9;
  return b;
}

function frame(tid, ms, bytes) {
  const dv = new DataView(new ArrayBuffer(FEED_HDR));
  dv.setBigUint64(0, BigInt(tid), true);
  dv.setBigUint64(8, BigInt(ms), true);
  dv.setUint32(16, bytes.length, true);
  return Buffer.concat([Buffer.from(new Uint8Array(dv.buffer)), bytes]);
}

// Feed `wire` through parseFeed in chunks of `size` bytes, accumulating.
function drain(wire, size) {
  let buf = new Uint8Array(0), got = [];
  for (let i = 0; i < wire.length; i += size) {
    const chunk = wire.subarray(i, Math.min(i + size, wire.length));
    const merged = new Uint8Array(buf.length + chunk.length);
    merged.set(buf); merged.set(chunk, buf.length);
    const [frames, left] = parseFeed(merged);
    buf = left;
    for (const f of frames) got.push(f);
  }
  return {got: got, left: buf};
}

// The real tids are 15 digits, i.e. bigger than 2^32 -- the reason the header
// uses u64 and getBigUint64 rather than a pair of u32s.
const TIDS = [429728658691722, 429728659223864, 429728658783497,
              429728658756018];
const MS0 = Date.now();

// ---- build one mixed stream: 4 cameras, interleaved, varied frame sizes ----
const want = [];
const parts = [];
for (let i = 0; i < 24; i++) {
  const tid = TIDS[i % TIDS.length];
  const ms = MS0 + i * 50;
  const bytes = jpeg(300 + (i * 977) % 40000, i);
  want.push({tid: tid, ms: ms, bytes: bytes});
  parts.push(frame(tid, ms, bytes));
}
const wire = Buffer.concat(parts);
console.log('stream: %d frames, %d bytes, tids %s',
            want.length, wire.length, TIDS.join(','));

// ---- 1. every chunk size, including 1 byte and the whole thing -----------
for (const size of [1, 2, 7, 19, 20, 21, 1024, 65536, wire.length]) {
  const r = drain(wire, size);
  const ok = r.got.length === want.length && r.left.length === 0 &&
    r.got.every((f, i) =>
      f.tid === want[i].tid && f.ms === want[i].ms &&
      f.bytes.length === want[i].bytes.length &&
      f.bytes.every((v, j) => v === want[i].bytes[j]));
  check('chunk=' + size, ok,
        ok ? '' : 'got ' + r.got.length + '/' + want.length +
        ' left ' + r.left.length);
}

// ---- 2. a header split in the middle must be buffered, not lost ----------
{
  const buf = new Uint8Array(wire.subarray(0, 10));   // half a header
  const [f0, rest0] = parseFeed(buf);
  const [f1, rest1] = parseFeed(new Uint8Array(wire));  // header now complete
  check('half header buffered then completed',
        f0.length === 0 && rest0.length === 10 && rest1.length === 0 &&
        f1.length === want.length);
}

// ---- 3. truncated tail (server died mid-frame) stays buffered ------------
{
  const cut = wire.length - 5;
  const r = drain(wire.subarray(0, cut), 4096);
  check('truncated tail buffered',
        r.got.length === want.length - 1 && r.left.length > 0,
        'frames ' + r.got.length + ' left ' + r.left.length);
}

// ---- 4. a corrupt length must not throw or eat the whole stream ----------
// 0xFFFFFFF0 is over the 4 MB sanity cap, so the parser must bail to an empty
// buffer rather than trying to allocate ~4 GB.
{
  const bogus = new Uint8Array(FEED_HDR);
  const dv = new DataView(bogus.buffer);
  dv.setBigUint64(0, BigInt(TIDS[0]), true);
  dv.setBigUint64(8, BigInt(MS0), true);
  dv.setUint32(16, 0xfffffff0, true);
  const mixed = Buffer.concat([Buffer.from(bogus), wire]);
  let threw = false, frames = null, left = null;
  try { [frames, left] = parseFeed(new Uint8Array(mixed)); }
  catch (e) { threw = true; }
  check('corrupt length resyncs without throwing',
        !threw && frames.length === 0 && left.length === 0,
        'frames ' + (frames && frames.length) + ' left ' + (left && left.length));
}

// ---- 5. the post-resync stream is readable again ------------------------
{
  const [frames, left] = parseFeed(new Uint8Array(wire));
  check('clean stream after resync',
        frames.length === want.length && left.length === 0);
}

console.log(fails ? '\nFAILED: ' + fails + '\n' : '\nall good\n');
process.exit(fails ? 1 : 0);
