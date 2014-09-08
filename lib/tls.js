var util = require('util');
var stream = require('stream');
var tls = require('tls.js');

var id = 0;
function TLSStream(mitm, tcp) {
  this.mitm = mitm;
  this.id = id++;

  this.tcp = tcp;
  this.server = new TLSState(this, 'server');
  this.client = new TLSState(this, 'client');

  this.crypto = mitm.crypto;

  this.preMaster = null;
  this.master = null;

  this.info = null;
  this.version = null;

  tcp.server.pipe(this.server.parser);
  tcp.client.pipe(this.client.parser);

  var self = this;
  this.client.parser.on('data', function(data) {
    if (data.handshakeType === 'client_hello') {
      self.client.hello = data;
      self.client.random = data.random;
    } else if (data.handshakeType === 'client_key_exchange') {
      self.rsaKeyEx(data);
    } else if (data.type === 'application_data') {
      for (var i = 0; i < data.chunks.length; i++)
        self.client.write(data.chunks[i]);
    } else if (data.type === 'alert') {
      self.client.push(null);
    }
  });

  this.server.parser.on('data', function(data) {
    if (data.handshakeType === 'server_hello') {
      self.server.hello = data;
      self.server.random = data.random;
      self.setCipher(data.cipherSuite, data.version);

      // Set pending preMaster
      if (self.preMaster)
        self.setPreMaster(self.preMaster);
    } else if (data.type === 'application_data') {
      for (var i = 0; i < data.chunks.length; i++)
        self.server.write(data.chunks[i]);
    } else if (data.type === 'alert') {
      self.server.push(null);
    }
  });
};
exports.TLSStream = TLSStream;

TLSStream.prototype.setCipher = function setCipher(cipher, version) {
  this.info = tls.constants.cipherInfoByName[cipher];
  if (!this.info || this.info.dh || this.info.auth !== 'rsa')
    return this.destroy();

  this.version = version;
};

TLSStream.prototype.rsaKeyEx = function rsaKeyEx(frame) {
  var keyEx = this.client.parser.parseRSAKeyEx(frame);
  if (!keyEx)
    return this.destroy();

  var out = new Buffer(this.mitm.key.size());
  var pre = this.mitm.crypto.decryptPrivate(out, keyEx, this.mitm.key);
  if (pre.length != 48 || pre[0] !== 3)
    return this.destroy();

  this.setPreMaster(pre);
};

TLSStream.prototype.setPreMaster = function setPreMaster(pre) {
  if (!this.client.hello)
    return this.destroy();

  // Set pending pre-master
  if (!this.server.hello) {
    this.preMaster = pre;
    this.tcp.client.pause();
    return;
  }
  this.preMaster = null;

  var prf = this.mitm.crypto.prf(this.version >= 0x0303 ? this.info.prf :
                                                          'md5/sha1');

  var secrets = tls.utils.deriveSecrets(this.info,
                                        prf,
                                        pre,
                                        this.client.random,
                                        this.server.random);

  this.client.key = secrets.client.key;
  this.server.key = secrets.server.key;
  this.client.iv = secrets.client.iv;
  this.server.iv = secrets.server.iv;

  var decipherAlg = this.mitm.crypto.decipher(this.info.bulk);

  this.client.decipher = decipherAlg(this.client.key, this.client.iv);
  this.server.decipher = decipherAlg(this.server.key, this.server.iv);
};

TLSStream.prototype.destroy = function destroy() {
  this.tcp.server.unpipe(this.server.parser);
  this.tcp.client.unpipe(this.client.parser);
  this.tcp.destroy();
};

function TLSState(conn, type) {
  stream.PassThrough.call(this);

  this.conn = conn;
  this.parser = tls.parser.create(this);

  this.encrypted = false;
  this.type = type;

  this.decipher = null;

  this.hello = null;
  this.random = null;
  this.key = null;
  this.iv = null;

  var self = this;
  this.parser.on('error', function(err) {
    self.conn.destroy();
  });
}
util.inherits(TLSState, stream.PassThrough);

//
// Just some hooks for decryption!
//

TLSState.prototype.switchToPending = function switchToPending() {
  this.encrypted = true;
};

TLSState.prototype.shouldDecrypt = function shouldDecrypt() {
  return this.encrypted;
};

TLSState.prototype.decrypt = function decrypt(data) {
  // Decipher data
  var out = new Buffer(data.length);
  this.decipher.write(out, data);

  var info = this.conn.info;
  if (info.bulk.cbc) {
    var ivLen = 0;
    if (this.conn.version >= 0x0302 && info.type === 'block')
      ivLen = info.bulk.size / 8;

    // Strip IV and padding
    var pad = out[out.length - 1] + 1;
    out = out.slice(ivLen, out.length - pad);
  }

  // Just strip the mac
  var macSize = info.macSize / 8;
  out = out.slice(0, -macSize);

  return out;
};
