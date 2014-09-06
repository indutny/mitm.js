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
var multiparty = require('multiparty');
var ascii = require('ascii');
var async = require('async');
var TP = require('tcpdump-parser');
var tp = new TP();

tp.on('error', function(err) {
  console.log('TCPDump Parser error', err);
});

process.stdin.pipe(tp).pipe(mitm);

mitm.on('request', function(req) {
  console.log(req.method, req.url);
  var form = new multiparty.Form();

  if (req.method !== 'POST')
    return;

  form.parse(req, function(err, fields, files) {
    if (err)
      return;

    asciify(files, function(err, pics) {
      if (err)
        return;

      console.log('Got request %s', req.url);
      console.log('  fields:');
      Object.keys(fields).forEach(function(name) {
        fields[name].forEach(function(value) {
          console.log('    %s: %s', name, value);
        });
      });
      console.log('  pics:');
      pics.forEach(function(pic) {
        console.log('    pic %s', pic.key);
        console.log(pic.pic);
      });
    });
  });
}).on('error', function(err) {
  console.log(err);
});

function asciify(files, cb) {
  async.map(Object.keys(files), function(key, cb) {
    async.map(files[key], function(file, cb) {
      if (!/\.(png|jpg)$/.test(file.path))
        return cb(null, null);

      var pic = new ascii(file.path);
      pic.convert(cb);
    }, function(err, pics) {
      if (err)
        return cb(err);

      pics = pics.filter(function(pic) { return !!pic; });
      cb(null, pics.map(function(pic) {
        return {
          key: key,
          pic: pic
        };
      }));
    });
  }, function(err, files) {
    if (err)
      return cb(err);

    var acc = [];
    for (var i = 0; i < files.length; i++)
      acc = acc.concat(files[i]);

    cb(null, acc);
  })
}
