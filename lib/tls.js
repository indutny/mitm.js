var util = require('util');
var stream = require('stream');
var tls = require('tls.js');

function TLSStream(mitm, tcp) {
  this.mitm = mitm;

  this.tcp = tcp;
  this.server = {
    state: new TLSState(this, 'server'),
    parser: null,
    random: null,
    key: null,
    iv: null,
    decipher: null,
    stream: new stream.PassThrough()
  };
  this.client = {
    state: new TLSState(this, 'client'),
    parser: null,
    random: null,
    key: null,
    iv: null,
    decipher: null,
    stream: new stream.PassThrough()
  };
  this.server.parser = tls.parser.create(this.server.state);
  this.client.parser = tls.parser.create(this.client.state);

  this.crypto = mitm.crypto;

  this.master = null;

  this.info = null;
  this.version = null;

  tcp.server.pipe(this.server.parser);
  tcp.client.pipe(this.client.parser);

  this.server.parser.on('error', function(err) {
    tcp.destroy();
  });
  this.client.parser.on('error', function(err) {
    tcp.destroy();
  });

  var self = this;
  this.client.parser.on('data', function(data) {
    if (data.handshakeType === 'client_hello') {
      self.client.random = data.random;
    } else if (data.handshakeType === 'client_key_exchange') {
      self.rsaKeyEx(data);
    } else if (data.type === 'application_data') {
      for (var i = 0; i < data.chunks.length; i++)
        self.client.stream.write(data.chunks[i]);
    } else if (data.type === 'alert') {
      self.client.stream.push(null);
    }
  });

  this.server.parser.on('data', function(data) {
    if (data.handshakeType === 'server_hello') {
      self.server.random = data.random;
      self.setCipher(data.cipherSuite, data.version);
    } else if (data.type === 'application_data') {
      for (var i = 0; i < data.chunks.length; i++)
        self.server.stream.write(data.chunks[i]);
    } else if (data.type === 'alert') {
      self.server.stream.push(null);
    }
  });
};
exports.TLSStream = TLSStream;

TLSStream.prototype.setCipher = function setCipher(cipher, version) {
  this.info = tls.constants.cipherInfoByName[cipher];
  if (this.info.auth !== 'rsa')
    return this.tcp.destroy();

  this.version = version;
};

TLSStream.prototype.rsaKeyEx = function rsaKeyEx(frame) {
  var keyEx = this.client.parser.parseRSAKeyEx(frame);
  if (!keyEx)
    return false;

  var out = new Buffer(this.mitm.key.size());
  this.setPreMaster(this.mitm.crypto.decryptPrivate(out, keyEx, this.mitm.key));
};

TLSStream.prototype.setPreMaster = function setPreMaster(pre) {
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

  this.client.state.decipher = this.mitm.crypto.decipher(this.info.bulk)(
      this.client.key,
      this.client.iv);
  this.server.state.decipher = this.mitm.crypto.decipher(this.info.bulk)(
      this.server.key,
      this.server.iv);
};

TLSStream.prototype.destroy = function destroy() {
  this.tcp.destroy();
};

function TLSState(conn, type) {
  this.conn = conn;
  this.encrypted = false;
  this.type = type;

  this.decipher = null;
}

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
