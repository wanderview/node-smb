'use strict';

var net = require('net');
var NBSession = require('netbios-session');

function handleMessage(msg) {
  console.log('---> received message with [' + msg.length + '] bytes');
}

var server = net.createServer();
server.on('connection', function(socket) {
  console.log('---> connection from [' + socket.remoteAddress + ']');
  var nbsession = new NBSession({direct: true});

  nbsession.on('connect', function() {
    console.log('---> direct netbios session established');
  });

  nbsession.on('message', function(msg) {
    handleMessage(msg);
  });

  nbsession.attach(socket);
});

server.listen(445, function() {
  console.log('SMB server listening:');
});
