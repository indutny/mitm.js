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

process.stdin.pipe(new tp()).pipe(mitm);

mitm.on('request', function(req) {
  console.log('>>', req.url);

  var chunks = '';
  req.on('data', function(chunk) {
    chunks += chunk;
  });
  req.on('end', function() {
    if (!chunks)
      return;

    console.log(req.url, chunks);
  });
}).on('error', function(err) {
  console.log(err);
});
