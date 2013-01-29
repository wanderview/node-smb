// Copyright (c) 2013, Benjamin J. Kelly ("Author")
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'use strict';

module.exports = unpack;

var flags = require('./flags');
var binary = require('binary');

var COMMAND_TO_STRING = {
  0x72: 'negotiate'
};

var COMMAND_PROC = {
  request: {
    negotiate: unpackNegotiate
  },
  reply: {
  }
};

function unpack(buf) {
  var parser = binary.parse(buf);
  var raw = parser.buffer('protocol', 4)
                  .word8('command')
                  .word32le('status')
                  .word8('flags')
                  .word16le('flags2')
                  .word16le('extra.pidHigh')
                  .buffer('extra.signature', 8)
                  .skip(2)
                  .word16le('tid')
                  .word16le('pid')
                  .word16le('uid')
                  .word16le('mid')
                  .word8('params.wordCount')
                  .buffer('params.words', 2*parser.vars['params']['wordCount'])
                  .word16le('data.byteCount')
                  .buffer('data.bytes', 'data.byteCount')
                  .vars;

  var msg = {
    command: COMMAND_TO_STRING[raw.command],
    status: raw.status,
    flags: flags.toObj(raw.flags, raw.flags2),
    extra: {
      pidHigh: raw.extra.pidHigh,
      signature: raw.extra.signature
    },
    tid: raw.tid,
    pid: raw.pid,
    uid: raw.uid,
    mid: raw.mid,
    raw: raw
  };

  var proc = COMMAND_PROC[(msg.flags.reply ? 'reply' : 'request')][msg.command];
  if (typeof proc === 'function') {
    proc(msg);
  }

  return msg;
}

function unpackNegotiate(msg) {
  msg.dialects = [];

  var count = 0;

  binary.parse(msg.raw.data.bytes).loop(function (end, vars) {
    this.skip(1);
    count += 1;

    this.scan('dialect', new Buffer([0]));
    var dialect = vars['dialect'].toString();

    msg.dialects.push(dialect);
    count += dialect.length + 1;

    if (count >= msg.raw.data.byteCount) {
      end();
    }
  });
}
