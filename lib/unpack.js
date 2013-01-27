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

var FLAGS_REPLY = 1 << 7;
var FLAGS_BATCH_OPLOCK = 1 << 6;
var FLAGS_OPLOCK = 1 << 5;
var FLAGS_CANONICAL_PATHNAMES = 1 << 4;
var FLAGS_CASELESS_PATHNAMES = 1 << 3;
// bit 2 reserved
// bit 1 only applies to NetBEUI which we are not supporting
var FLAGS_SUPPORT_LOCKREAD = 1 << 0;

var FLAGS2_UNICODE_STRINGS = 1 << 15;
var FLAGS2_STATUS = 1 << 14;
var FLAGS2_READ_IF_EXECUTE = 1 << 13;
var FLAGS2_DFS_PATHNAMES = 1 << 12;
var FLAGS2_EXTENDED_SECURITY = 1 << 11;
// bit 10 reserved
// bit 9 reserved
// bit 8 reserved
// bit 7 reserved
var FLAGS2_IS_LONG_NAME = 1 << 6;
// bit 5 reserved
// bit 4 reserved
// bit 3 reserved
var FLAGS2_SECURITY_SIGNATURE = 1 << 2;
var FLAGS2_EAS = 1 << 1;
var FLAGS2_KNOWS_LONG_NAMES = 1 << 0;

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
                  .word16le('extra.reserved')
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
    type: (raw.flags & FLAGS_REPLY) ? 'reply' : 'request',
    flags: {
      oplock: false,
      pathnames: {
        form: (raw.flags & FLAGS_CANONICAL_PATHNAMES) ? 'canonical' : 'host',
        case: (raw.flags & FLAGS_CASELESS_PATHNAMES) ? 'caseless' : 'case-sensitive',
        format: {
          is: (raw.flags2 & FLAGS2_IS_LONG_NAME) ? 'long' : '8.3',
          supports: (raw.flags2 & FLAGS2_KNOWS_LONG_NAMES) ? 'long' : '8.3'
        },
        type: (raw.flags2 & FLAGS2_DFS_PATHNAMES) ? 'dfs' : 'normal'
      },
      lockread: (raw.flags & FLAGS_SUPPORT_LOCKREAD) ? 'supported' : false,
      strings: (raw.flags2 & FLAGS2_UNICODE_STRINGS) ? 'unicode' : 'ascii',
      status: (raw.flags2 & FLAGS2_STATUS) ? 'NT' : 'DOS',
      readIfExec: !!(raw.flags2 & FLAGS2_READ_IF_EXECUTE),
      security: {
        support: (raw.flags2 & FLAGS2_EXTENDED_SECURITY) ? 'extended' : 'normal',
        signature: !!(raw.flags2 & FLAGS2_SECURITY_SIGNATURE)
      },
      attributes: (raw.flags2 & FLAGS2_EAS) ? 'extended' : 'normal'
    },
    raw: raw
  };

  if (raw.flags & FLAGS_OPLOCK) {
    raw.flags.oplock = {
      type: (raw.flags & FLAGS_BATCH_OPLOCK) ? 'batch' : 'exclusive'
    }
  }

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
