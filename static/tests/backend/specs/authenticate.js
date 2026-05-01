'use strict';

const assert = require('assert').strict;
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const settings = require('ep_etherpad-lite/node/utils/Settings');

const pluginPath = path.resolve(__dirname, '..', '..', '..', '..', 'ep_hash_auth.js');
const loadPlugin = () => {
  delete require.cache[require.resolve(pluginPath)];
  return require(pluginPath);
};

const sha512Hex = (s) => crypto.createHash('sha512').update(s).digest('hex');

const basicHeader =
    (user, pass) => `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;

const callAuthenticate = (plugin, headers) => new Promise((resolve) => {
  const req = {headers, session: {}};
  plugin.authenticate('authenticate', {req}, (result) => {
    resolve({result, session: req.session});
  });
});

describe('ep_hash_auth authenticate', function () {
  let tmpdir;
  let plugin;
  let originalUsers;
  let originalEpHashAuth;

  // eslint-disable-next-line mocha/no-synchronous-tests
  before(function () {
    tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep_hash_auth-'));
    originalUsers = settings.users;
    originalEpHashAuth = settings.ep_hash_auth;
    settings.users = {};
    settings.ep_hash_auth = {
      hash_typ: 'sha512',
      hash_dig: 'hex',
      hash_dir: tmpdir,
      hash_ext: '/.hash',
      hash_adm: false,
      displayname_ext: '/.displayname',
      hash_adm_ext: '/.adm',
    };
    plugin = loadPlugin();
  });

  // eslint-disable-next-line mocha/no-synchronous-tests
  after(function () {
    settings.users = originalUsers;
    settings.ep_hash_auth = originalEpHashAuth;
    fs.rmSync(tmpdir, {recursive: true, force: true});
  });

  // eslint-disable-next-line mocha/no-synchronous-tests
  beforeEach(function () {
    settings.users = {};
  });

  const writeUser = (username, files) => {
    const dir = path.join(tmpdir, username);
    fs.mkdirSync(dir, {recursive: true});
    for (const [name, contents] of Object.entries(files)) {
      fs.writeFileSync(path.join(dir, name), contents);
    }
  };

  describe('no/invalid auth header', function () {
    it('returns false when no Authorization header is set', async function () {
      const {result} = await callAuthenticate(plugin, {});
      assert.deepEqual(result, [false]);
    });

    it('returns false for non-Basic auth schemes', async function () {
      const {result} = await callAuthenticate(plugin, {authorization: 'Bearer abc'});
      assert.deepEqual(result, [false]);
    });
  });

  describe('hash_dir-based auth (sha512)', function () {
    it('authenticates when .hash matches the sha512 hex of the password', async function () {
      writeUser('alice', {'.hash': sha512Hex('s3cret')});
      const {result, session} = await callAuthenticate(
          plugin, {authorization: basicHeader('alice', 's3cret')});
      assert.deepEqual(result, [true]);
      assert.equal(session.user.username, 'alice');
      assert.equal(session.user.is_admin, false);
    });

    it('tolerates trailing newline in the .hash file', async function () {
      writeUser('bob', {'.hash': `${sha512Hex('hunter2')}\n`});
      const {result} = await callAuthenticate(
          plugin, {authorization: basicHeader('bob', 'hunter2')});
      assert.deepEqual(result, [true]);
    });

    it('rejects a wrong password', async function () {
      writeUser('carol', {'.hash': sha512Hex('right')});
      const {result} = await callAuthenticate(
          plugin, {authorization: basicHeader('carol', 'wrong')});
      assert.deepEqual(result, [false]);
    });

    it('rejects an unknown user (no hash file)', async function () {
      const {result} = await callAuthenticate(
          plugin, {authorization: basicHeader('nobody', 'whatever')});
      assert.deepEqual(result, [false]);
    });
  });

  describe('displayname loading', function () {
    it('loads a displayname when .displayname exists', async function () {
      writeUser('dan', {
        '.hash': sha512Hex('pw'),
        '.displayname': 'Daniel',
      });
      const {result, session} = await callAuthenticate(
          plugin, {authorization: basicHeader('dan', 'pw')});
      assert.deepEqual(result, [true]);
      assert.equal(session.user.displayname, 'Daniel');
    });

    it('trims trailing newline in the .displayname file', async function () {
      writeUser('eve', {
        '.hash': sha512Hex('pw'),
        '.displayname': 'Eve\n',
      });
      const {session} = await callAuthenticate(
          plugin, {authorization: basicHeader('eve', 'pw')});
      assert.equal(session.user.displayname, 'Eve');
    });

    it('leaves displayname undefined when .displayname is missing', async function () {
      writeUser('frank', {'.hash': sha512Hex('pw')});
      const {session} = await callAuthenticate(
          plugin, {authorization: basicHeader('frank', 'pw')});
      assert.equal(session.user.displayname, undefined);
    });
  });

  describe('hash_adm_ext (per-user admin flag)', function () {
    it('marks user admin when .adm contains "true"', async function () {
      writeUser('grace', {
        '.hash': sha512Hex('pw'),
        '.adm': 'true',
      });
      const {session} = await callAuthenticate(
          plugin, {authorization: basicHeader('grace', 'pw')});
      assert.equal(session.user.is_admin, true);
    });

    it('marks user admin when .adm contains "true\\n" (trailing newline)', async function () {
      // Regression: `echo "true" > .adm` writes a trailing newline. A naïve
      // `contents === 'true'` check would silently fall back to hash_adm.
      writeUser('heidi', {
        '.hash': sha512Hex('pw'),
        '.adm': 'true\n',
      });
      const {session} = await callAuthenticate(
          plugin, {authorization: basicHeader('heidi', 'pw')});
      assert.equal(session.user.is_admin, true);
    });

    it('marks user non-admin when .adm contains "false"', async function () {
      writeUser('ivan', {
        '.hash': sha512Hex('pw'),
        '.adm': 'false',
      });
      const {session} = await callAuthenticate(
          plugin, {authorization: basicHeader('ivan', 'pw')});
      assert.equal(session.user.is_admin, false);
    });

    it('falls back to hash_adm when .adm is missing', async function () {
      settings.ep_hash_auth.hash_adm = true;
      try {
        const reloaded = loadPlugin();
        writeUser('judy', {'.hash': sha512Hex('pw')});
        const {session} = await callAuthenticate(
            reloaded, {authorization: basicHeader('judy', 'pw')});
        assert.equal(session.user.is_admin, true);
      } finally {
        settings.ep_hash_auth.hash_adm = false;
        plugin = loadPlugin();
      }
    });
  });

  describe('settings.users-based auth', function () {
    it('authenticates against settings.users[name].hash', async function () {
      settings.users.kate = {
        hash: sha512Hex('secret'),
        is_admin: true,
        displayname: 'Kate',
      };
      const {result, session} = await callAuthenticate(
          plugin, {authorization: basicHeader('kate', 'secret')});
      assert.deepEqual(result, [true]);
      assert.equal(session.user.is_admin, true);
      assert.equal(session.user.displayname, 'Kate');
    });

    it('rejects wrong password against settings.users', async function () {
      settings.users.leo = {hash: sha512Hex('right')};
      const {result} = await callAuthenticate(
          plugin, {authorization: basicHeader('leo', 'wrong')});
      assert.deepEqual(result, [false]);
    });
  });
});
