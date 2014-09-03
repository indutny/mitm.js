var stream = require('stream');
var util = require('util');
var EventEmitter = require('events').EventEmitter;

function LittleParser() {
  EventEmitter.call(this);

  this.client = new stream.PassThrough();
  this.server = new stream.PassThrough();

  this.side = 'req';
  this.state = 'line';
  this.waiting = null;

  this.buffer = {
    req: new Buffer(0),
    res: new Buffer(0)
  };

  this.req = null;
  this.res = null;

  var self = this;
  this.client.on('data', function(chunk) {
    self.buffer.req = Buffer.concat([ self.buffer.req, chunk ]);
    self.execute();
  });
  this.server.on('data', function(chunk) {
    self.buffer.res = Buffer.concat([ self.buffer.res, chunk ]);
    self.execute();
  });
}
util.inherits(LittleParser, EventEmitter);
exports.LittleParser = LittleParser;

LittleParser.prototype.execute = function execute() {
  while (true) {
    var buf = this.buffer[this.side];
    if (buf.length === 0)
      break;

    var start = buf.length;

    if (this.side === 'req' && this.state === 'line')
      this.parseReqLine(buf);
    else if (this.side === 'res' && this.state === 'line')
      this.parseResLine(buf);
    else if (this.state === 'headers')
      this.parseHeaders(buf);
    else if (this.state === 'chunked-size')
      this.parseChunkedSize(buf);
    else if (this.state === 'body')
      this.parseBody(buf);
    else if (this.state === 'after-body')
      this.parseAfterBody(buf);

    if (start === this.buffer[this.side].length)
      break;
  }
};

LittleParser.prototype.getLine = function getLine(buf) {
  for (var i = 0; i < buf.length; i++) {
    if (buf[i] === 13 && buf[i + 1] === 10) {
      var res = buf.slice(0, i).toString('');
      this.buffer[this.side] = buf.slice(i + 2);
      return res;
    } else if (buf[i] === 10) {
      var res = buf.slice(0, i).toString('');
      this.buffer[this.side] = buf.slice(i + 1);
      return res;
    }
  }

  return null;
};

LittleParser.prototype._error = function _error(msg) {
  this.emit('error', new Error(msg));
};

LittleParser.prototype.parseReqLine = function parseReqLine(buf) {
  var line = this.getLine(buf);
  if (line === null)
    return;

  var match = line.match(/^(\w+)\s+([^\s]+)\s+HTTP\/1.1$/i);
  if (!match)
    return this._error('Invalid request line');

  this.req = new Request(match[1], match[2]);
  this.state = 'headers';
};

LittleParser.prototype.parseResLine = function parseResLine(buf) {
  var line = this.getLine(buf);
  if (line === null)
    return;

  var match = line.match(/^HTTP\/1.1\s+(\d+)\s(.+)$/i);
  if (!match)
    return this._error('Invalid response line');

  this.res = new Response(this.req, match[1] | 0, match[2]);
  this.req.emit('response', this.res);
  this.state = 'headers';
};

LittleParser.prototype.parseHeaders = function parseHeaders(buf) {
  var line = this.getLine(buf);
  if (line === null)
    return;

  var r = this.side === 'req' ? this.req : this.res;

  // Start of body
  if (line === '') {
    this.emit('request', this.req);
    if (this.side === 'req' && this.state === 'headers' && r.method === 'GET') {
      this.side = 'res';
      this.state = 'line';
      this.req.push(null);
    } else {
      if (!r.headers.hasOwnProperty('content-length') &&
          r.headers['transfer-encoding'] !== 'chunked') {
        return this._error('No Content-Length header');
      }

      this.waiting = r.headers['content-length'] | 0;
      if (r.headers['transfer-encoding'] === 'chunked') {
        this.state = 'chunked-size';
      } else {
        this.state = 'body';
      }
    }
    return;
  }

  // Headers
  var match = line.match(/^([^\s]+)\s*:\s*(.+)$/);
  if (!match)
    return this._error('Invalid header line');

  r.headers[match[1].toLowerCase()] = match[2];
};

LittleParser.prototype.parseChunkedSize = function parseChunkedSize(buf) {
  var size = this.getLine(buf);
  if (size === null)
    return;

  this.waiting = parseInt(size, 16);
  this.state = 'body';
};

LittleParser.prototype.parseBody = function parseBody(buf) {
  if (buf.length < this.waiting)
    return;

  var chunk = buf.slice(0, this.waiting);
  this.buffer[this.side] = buf.slice(this.waiting);

  var r = this.side === 'req' ? this.req : this.res;
  if (chunk.length === 0)
    r.push(null);
  else
    r.push(chunk);

  if (r.headers['transfer-encoding'] === 'chunked') {
    this.state = 'after-body';
  } else {
    if (chunk.length !== 0)
      r.push(null);
    this.side = this.side === 'req' ? 'res' : 'req';
    this.state = 'line';
  }
};

LittleParser.prototype.parseAfterBody = function parseAfterBody(buf) {
  var line = this.getLine(buf);
  if (line !== '')
    return;

  var r = this.side === 'req' ? this.req : this.res;

  if (r.headers['transfer-encoding'] === 'chunked' &&
      !r._readableState.ended) {
    this.state = 'chunked-size';
  } else {
    this.side = this.side === 'req' ? 'res' : 'req';
    this.state = 'line';
  }
};

function Request(method, url) {
  stream.PassThrough.call(this);

  this.method = method;
  this.url = url;
  this.headers = {};
}
util.inherits(Request, stream.PassThrough);

function Response(req, code, reason) {
  stream.PassThrough.call(this);

  this.req = req;
  this.statusCode = code;
  this.reason = reason;
  this.headers = {};
}
util.inherits(Response, stream.PassThrough);
