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

module.exports.toObj = toObj;
module.exports.fromObj = fromObj;

// TODO: Double check the reserved and unused bits with the latest docs.
//       Wireshark output suggests many of these are now used.

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
var FLAGS2_SECURITY_SIGNATURE_REQUIRED = 1 << 4;
// bit 3 reserved
var FLAGS2_SECURITY_SIGNATURE = 1 << 2;
var FLAGS2_EAS = 1 << 1;
var FLAGS2_KNOWS_LONG_NAMES = 1 << 0;

function toObj(flags, flags2) {
  var rtn = {
    reply: !!(flags & FLAGS_REPLY),
    oplock: {
      enabled: !!(flags & FLAGS_OPLOCK),
      batch: !!(flags & FLAGS_BATCH_OPLOCK)
    },
    pathnames: {
      canonical: !!(flags & FLAGS_CANONICAL_PATHNAMES),
      caseless: !!(flags & FLAGS_CASELESS_PATHNAMES),
      long: {
        enabled: !!(flags2 & FLAGS2_IS_LONG_NAME),
        supported: !!(flags2 & FLAGS2_KNOWS_LONG_NAMES),
      },
      dfs: !!(flags2 & FLAGS2_DFS_PATHNAMES)
    },
    lockread: !!(flags & FLAGS_SUPPORT_LOCKREAD),
    unicode: !!(flags2 & FLAGS2_UNICODE_STRINGS),
    status: (flags2 & FLAGS2_STATUS) ? 'NT' : 'DOS',
    readIfExec: !!(flags2 & FLAGS2_READ_IF_EXECUTE),
    security: {
      extended: !!(flags2 & FLAGS2_EXTENDED_SECURITY),
      signature: {
        enabled: !!(flags2 & FLAGS2_SECURITY_SIGNATURE),
        required: !!(flags2 & FLAGS2_SECURITY_SIGNATURE_REQUIRED)
      }
    },
    eas: !!(flags2 & FLAGS2_EAS)
  };

  return rtn;
}

function fromObj(obj) {
  var rtn = {
    flags: 0x00,
    flags2: 0x0000
  };

  rtn.flags = (obj.reply ? FLAGS_REPLY : 0)
            | (obj.oplock.enabled ? FLAGS_OPLOCK : 0)
            | (obj.oplock.batch ? FLAGS_BATCH_OPLOCK : 0)
            | (obj.pathnames.canonical ? FLAGS_CANONICAL_PATHNAMES : 0)
            | (obj.pathnames.caseless ? FLAGS_CASELESS_PATHNAMES : 0)
            | (obj.lockread ? FLAGS_SUPPORT_LOCKREAD : 0);

  rtn.flags2 = (obj.pathnames.long.enabled ? FLAGS2_IS_LONG_NAME : 0)
             | (obj.pathnames.long.supported ? FLAGS2_KNOWS_LONG_NAMES : 0)
             | (obj.pathnames.dfs ? FLAGS2_DFS_PATHNAMES : 0)
             | (obj.unicode ? FLAGS2_UNICODE_STRINGS : 0)
             | (obj.status === 'NT' ? FLAGS2_STATUS : 0)
             | (obj.readIfExec ? FLAGS2_READ_IF_EXECUTE : 0)
             | (obj.security.extended ? FLAGS2_EXTENDED_SECURITY : 0)
             | (obj.security.signature.enabled ? FLAGS2_SECURITY_SIGNATURE : 0)
             | (obj.security.signature.required ? FLAGS2_SECURITY_SIGNATURE_REQUIRED : 0)
             | (obj.eas ? FLAGS2_EAS : 0);

  return rtn;
}
