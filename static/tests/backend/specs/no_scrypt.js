'use strict';

const assert = require('assert').strict;
const fs = require('fs');
const path = require('path');

const pluginSrc = path.resolve(__dirname, '..', '..', '..', '..', 'ep_hash_auth.js');
const readme = path.resolve(__dirname, '..', '..', '..', '..', 'README.md');

describe(__filename, function () {
  it('ep_hash_auth.js no longer references the unmaintained scrypt module (#10)', function () {
    const src = fs.readFileSync(pluginSrc, 'utf8');
    // The comment block explaining that scrypt was dropped is allowed; what
    // we guard against is an `optionalRequire('scrypt', ...)` or any call
    // into a `scrypt` variable that used to shadow the npm module.
    assert(!/optionalRequire\(\s*['"]scrypt['"]/.test(src),
        'should not attempt to optionalRequire the deprecated `scrypt` npm module');
    assert(!/\bscrypt\s*\.\s*verifyKdfSync\b/.test(src),
        'should not call into the removed scrypt.verifyKdfSync path');
    assert(!/\bconst\s+scrypt\s*=/.test(src),
        'should not bind a `scrypt` module variable');
  });

  it('README no longer documents the scrypt hash-generation recipe (#10)', function () {
    const md = fs.readFileSync(readme, 'utf8');
    assert(!/require\(['"]scrypt['"]\)/.test(md),
        'README should not show the deprecated scrypt recipe');
  });
});
