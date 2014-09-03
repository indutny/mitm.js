#!/usr/bin/env node
var argv = require('yargs')
    .usage('Usage: $0 --key private-key.pem --ticket-key tls-ticket-key.pem')
    .demand('key')
    .alias('k', 'key')
    .alias('t', 'ticket-key')
    .argv;

var fs = require('fs');

argv.key = fs.readFileSync(argv.key);
if (argv['ticket-key'])
  argv['ticket-key'] = fs.readFileSync(argv['ticket-key']);

var mitm = require('../').createStream(argv);
var tp = require('tcpdump-parser');
var Ascii = require('ascii');

process.stdin.pipe(new tp()).pipe(mitm);

mitm.on('request', function(req) {
  if (!/\.(png|jpg|jpeg)$/.test(req.url))
    return;

  req.on('response', function(res) {
    if (res.statusCode < 200 || res.statusCode >= 500)
      return;

    var chunks = [];
    res.on('data', function(chunk) {
      chunks.push(chunk);
    });
    res.on('end', function() {
      var content = Buffer.concat(chunks);

      var ascii = new Ascii('who cares about source');
      ascii.load = function(callback) {
        callback(null, content);
      };

      ascii.convert(function(err, art) {
        if (err)
          throw err;

        console.log(req.url);
        console.log(art);
      });
    });
  });
}).on('error', function(err) {
  console.log(err);
});
