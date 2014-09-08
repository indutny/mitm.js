#!/usr/bin/env node
var multiparty = require('multiparty');
var TcpdumpParser = require('tcpdump-parser');
var argv = require('yargs')
    .usage('Usage: $0 --key private-key.pem --ticket-key tls-ticket-key.pem')
    .demand('key')
    .alias('k', 'key')
    .argv;

var fs = require('fs');

argv.key = fs.readFileSync(argv.key);

var mitm = require('../').createStream(argv);
var dumpParser = new TcpdumpParser();

dumpParser.on('error', function(err) {
  console.log('TCPDump Parser error', err);
});

process.stdin.pipe(dumpParser)
             .pipe(mitm)
             .on('request', onRequest)
             .on('error', function(err) {
               console.log(err);
             });

function onRequest(req) {
  console.log(req.method, 'https://' + req.headers.host + req.url);
  var form = new multiparty.Form();

  if (req.method !== 'POST')
    return;

  form.parse(req, function(err, fields, files) {
    if (err)
      return;

    console.log('Got request %s', req.url);
    console.log('  fields:');
    Object.keys(fields).forEach(function(name) {
      fields[name].forEach(function(value) {
        console.log('    %s: %s', name, value);
      });
    });
  });
}
