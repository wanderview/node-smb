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

var flagsUtil = require('../lib/flags');

module.exports.zero = function(test) {
  test.expect(2);

  var f = 0x0;
  var f2 = 0x0;

  var o = flagsUtil.toObj(f, f2);
  var r = flagsUtil.fromObj(o);

  test.equal(f, r.flags);
  test.equal(f2, r.flags2);
  test.done();
};

module.exports.full = function(test) {
  test.expect(2);

  // set all bits except for unused or reserved
  var f = 0xff;
  f ^= (1 << 1);
  f ^= (1 << 2);

  var f2 = 0xffff;
  f2 ^= (1 << 3);
  f2 ^= (1 << 5);
  f2 ^= (1 << 7);
  f2 ^= (1 << 8);
  f2 ^= (1 << 9);
  f2 ^= (1 << 10);

  var o = flagsUtil.toObj(f, f2);
  var r = flagsUtil.fromObj(o);

  test.equal(f, r.flags);
  test.equal(f2, r.flags2);
  test.done();
};

module.exports.typical = function(test) {
  test.expect(2);

  var f = 0x18;
  var f2 = 0xc853;

  var o = flagsUtil.toObj(f, f2);
  var r = flagsUtil.fromObj(o);

  test.equal(f, r.flags);
  test.equal(f2, r.flags2);
  test.done();
};
