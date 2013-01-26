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

var binary = require('binary');

var FLAGS_REPLY = 0x7;

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
  var msg = parser.buffer('raw.protocol', 4)
                  .word8('raw.command')
                  .word32le('raw.status')
                  .word8('raw.flags')
                  .word16le('raw.flags2')
                  .word16le('raw.extra.pidHigh')
                  .buffer('raw.extra.signature', 8)
                  .word16le('raw.extra.reserved')
                  .word16le('raw.tid')
                  .word16le('raw.pid')
                  .word16le('raw.uid')
                  .word16le('raw.mid')
                  .word8('raw.params.wordCount')
                  .buffer('raw.params.words', 2*parser.vars['raw']['params']['wordCount'])
                  .word16le('raw.data.byteCount')
                  .buffer('raw.data.bytes', 'raw.data.byteCount')
                  .vars;

  msg.command = COMMAND_TO_STRING[msg.raw.command];
  msg.type = (msg.raw.flags & FLAGS_REPLY) ? 'reply' : 'request';

  var proc = COMMAND_PROC[msg.type][msg.command];
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
