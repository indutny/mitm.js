var util = require('util');
var stream = require('stream');

function TCPStream(mitm, seq) {
  stream.Transform.call(this);
  this._readableState.objectMode = true;
  this._writableState.objectMode = true;

  this.client = new stream.PassThrough();
  this.server = new stream.PassThrough();

  this.mitm = mitm;
  this.clientSeq = seq + 1;
  this.serverSeq = null;

  this.mitm.tcps[this.clientSeq] = this;
};
util.inherits(TCPStream, stream.Transform);
exports.TCPStream = TCPStream;

TCPStream.prototype._transform = function transform(packet, enc, cb) {
  cb();

  if (packet.syn && packet.ack) {
    this.serverSeq = packet.seq + 1;
    this.mitm.tcps[this.serverSeq] = this;
  }

  var stream;
  var seq;
  if (packet.seq === this.serverSeq) {
    stream = this.server;
    delete this.mitm.tcps[this.serverSeq];
    this.serverSeq += packet.data.length;
    seq = this.serverSeq;
  } else {
    stream = this.client;
    delete this.mitm.tcps[this.clientSeq];
    this.clientSeq += packet.data.length;
    seq = this.clientSeq;
  }

  if (packet.data.length !== 0)
    stream.push(packet.data);
  if (packet.fin)
    stream.push(null);
  else
    this.mitm.tcps[seq] = this;
};

TCPStream.prototype.destroy = function destroy() {
  delete this.mitm.tcps[this.clientSeq];
  delete this.mitm.tcps[this.serverSeq];
};
