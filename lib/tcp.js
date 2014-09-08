var util = require('util');
var stream = require('stream');

var id = 0;

function TCPStream(mitm, key) {
  stream.Transform.call(this);

  this.id = id++;
  this._readableState.objectMode = true;
  this._writableState.objectMode = true;

  this.client = new TCPSide(this, 'client');
  this.server = new TCPSide(this, 'server');
  this.client.opposite = this.server;
  this.server.opposite = this.client;

  this.state = 'initial';

  this.mitm = mitm;
  this.key = key;
};
util.inherits(TCPStream, stream.Transform);
exports.TCPStream = TCPStream;

TCPStream.prototype._transform = function transform(packet, enc, cb) {
  cb();

  var src = packet.raw.src.toString('hex') + '/' + packet.srcPort;
  var dst = packet.raw.dst.toString('hex') + '/' + packet.dstPort;

  var key = src + '/' + dst;
  var rkey = dst + '/' + src;

  var op;
  if (this.key === key) {
    op = 'send';
  } else if (this.key === rkey) {
    op = 'receive';
  } else {
    return;
  }

  // Looking on the packet capture from client's point of view
  var side;
  if (op === 'send')
    side = this.send(packet);
  else
    side = this.receive(packet);

  if (!side)
    return;

  // DATA flows
  side.addPending(packet);
  if (packet.ack)
    side.opposite.ackPending(packet.ackSeq);

  // Process FIN
  if (packet.fin) {
    side.closed = true;
    if (side.opposite.closed)
      this.destroy();
  }
};

TCPStream.prototype.send = function send(packet) {
  // Client don't send SYN+ACK
  if (packet.syn && packet.ack)
    return;

  // SYN sent
  if (this.state === 'initial') {
    if (!packet.syn)
      return;
    this.client.seq = packet.seq + 1;
    this.state = 'syn_sent';
    return;
  } else if (this.state === 'syn_sent') {
    // Ignore all packets
    return;
  } else if (this.state === 'syn_received') {
    if (!packet.ack)
      return;
    if (packet.ackSeq !== this.server.seq)
      return;
    this.server.ackSeq = this.server.seq;
    this.state = 'established';
    return;
  }

  // No SYN, when established
  if (packet.syn)
    return;

  return this.client;
};

TCPStream.prototype.receive = function receive(packet) {
  // Server don't send SYN
  if (packet.syn && !packet.ack)
    return;

  // Client starts first
  if (this.state === 'initial') {
    return;

  // SYN+ACK received
  } else if (this.state === 'syn_sent') {
    // Verify that SYN+ACK matches SYN
    if (this.client.seq !== packet.ackSeq)
      return;

    this.server.seq = packet.seq + 1;
    this.client.ackSeq = this.client.seq;
    this.state = 'syn_received';
    return;
  } else if (this.state === 'syn_received') {
    // Nothing
    return;
  }

  // No SYN when established
  if (packet.syn)
    return;

  return this.server;
};

TCPStream.prototype.destroy = function destroy() {
  this.emit('close');
};

function TCPSide(conn, label) {
  stream.PassThrough.call(this);

  this.conn = conn;
  this.label = label;

  // Sent data
  this.seq = null;

  this.pending = [];
  this.acked = [];
  this.closed = false;

  this.opposite = null;
}
util.inherits(TCPSide, stream.PassThrough);

TCPSide.prototype.sliceChunk = function sliceChunk(chunk, seq) {
  // Packet already acknowledged
  if (seq >= chunk.end)
    return false;

  // Packet partially acknowledged
  if (seq > chunk.start) {
    chunk.start = seq;
  }

  return true;
};

TCPSide.prototype.splitChunk = function splitChunk(chunk, seq) {
  if (chunk.end <= seq) {
    return {
      before: chunk,
      after: null
    };
  }

  var data = chunk.data;
  var pos = data.length - (seq - chunk.start);
  return {
    before: {
      start: chunk.start,
      end: seq,
      data: data.slice(0, pos)
    },
    after: {
      start: seq,
      end: chunk.end,
      data: data.slice(pos)
    }
  };
};

TCPSide.prototype.addPending = function addPending(packet) {
  if (packet.data.length === 0)
    return;

  var chunk = {
    start: packet.seq,
    end: packet.seq + packet.data.length,
    data: packet.data
  };
  if (!this.sliceChunk(chunk, this.seq))
    return;

  this.pending.push(chunk);

  // Sort by start first, and by reverse end then
  this.pending.sort(function(a, b) {
    return a.start < b.start ? -1 : a.start > b.start ? 1 : (b.end - a.end);
  });
};

TCPSide.prototype.ackPending = function ackPending(ackSeq) {
  for (var i = 0; i < this.pending.length && this.seq < ackSeq; i++) {
    var chunk = this.pending[i];

    // Remove extra bytes from chunk
    if (!this.sliceChunk(chunk, this.seq))
      continue;

    // Missing chunk, will cause a failure in other place, most likely
    if (chunk.start > this.seq) {
      console.error('Missing %d -> %d chunk', this.seq, chunk.start);
      this.push(new Buffer(chunk.start - this.seq));
      this.seq = chunk.start;
    }

    // Split chunk into part that will be written and the part that will
    // be queued again
    var split = this.splitChunk(chunk, ackSeq);

    this.push(split.before.data);
    this.seq = split.before.end;

    // More data to process in this chunk
    if (!split.after)
      continue;

    // Chunk is split - can't process data anymore
    this.pending[i] = split.after;
    break;
  }

  // Consume packets
  this.pending = this.pending.slice(i);
};
