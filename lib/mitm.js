var util = require('util');
var stream = require('stream');
var tls = require('tls.js');
var TCPStream = require('./tcp').TCPStream;
var TLSStream = require('./tls').TLSStream;
var LittleParser = require('./http').LittleParser;

function Stream(options) {
  stream.Writable.call(this);
  this._writableState.objectMode = true;

  this.crypto = tls.provider.node.create();
  this.key = this.crypto.toPrivateKey(options.key);

  this.tcps = {};
};
util.inherits(Stream, stream.Writable);

exports.Stream = Stream;
exports.createStream = function createStream(options) {
  return new Stream(options);
};

Stream.prototype._write = function write(packet, enc, cb) {
  cb();

  console.log(packet);
  if (packet.type !== 'tcp')
    return;

  var tcp = this.tcps[packet.seq];
  if (packet.syn) {
    if (packet.ack) {
      tcp = this.tcps[packet.ackSeq];

      tcp.write(packet);
    } else {
      if (tcp)
        return;

      tcp = new TCPStream(this, packet.seq);
      tcp.write(packet);

      var tls = new TLSStream(this, tcp);
      this._handleTLS(tls);
    }
  } else {
    if (!tcp)
      return;

    tcp.write(packet);
  }

};

Stream.prototype._error = function error(msg) {
  this.emit('error', msg instanceof Error ? msg : new Error(msg));
  return false;
};

Stream.prototype._handleTLS = function handleTLS(tls) {
  var lp = new LittleParser();
  var self = this;

  tls.client.stream.pipe(lp.client);
  tls.server.stream.pipe(lp.server);

  lp.on('request', function(req) {
    self.emit('request', req);
  });

  lp.on('error', function() {
    tls.destroy();
  });
};
