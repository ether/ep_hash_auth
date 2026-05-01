'use strict';

const assert = require('assert').strict;
const path = require('path');
// express + supertest are provided by Etherpad core's node_modules at test
// time; eslint can't see them from this plugin's source tree.
const express = require('express'); // eslint-disable-line n/no-missing-require
const supertest = require('supertest'); // eslint-disable-line n/no-missing-require

const pluginPath = path.resolve(__dirname, '..', '..', '..', '..', 'ep_hash_auth.js');

const buildApp = (plugin, sessionRef) => {
  const app = express();
  // Stub session middleware so the plugin can mutate `req.session.user`.
  app.use((req, res, next) => {
    req.session = sessionRef;
    next();
  });
  return new Promise((resolve, reject) => {
    plugin.expressCreateServer('expressCreateServer', {app}, (err) => {
      if (err) return reject(err);
      resolve(app);
    });
  });
};

describe('ep_hash_auth /logout endpoint', function () {
  let plugin;
  let session;
  let agent;

  // eslint-disable-next-line mocha/no-synchronous-tests
  before(async function () {
    delete require.cache[require.resolve(pluginPath)];
    plugin = require(pluginPath);
    session = {user: {username: 'alice', is_admin: false}};
    const app = await buildApp(plugin, session);
    agent = supertest(app);
  });

  it('returns 401 so the browser drops cached Basic creds', async function () {
    const res = await agent.get('/ep_hash_auth/logout');
    assert.equal(res.status, 401);
  });

  it('sets a fresh WWW-Authenticate realm distinct from the auth realm', async function () {
    const res = await agent.get('/ep_hash_auth/logout');
    assert.match(res.headers['www-authenticate'] || '', /^Basic realm="ep_hash_auth-logout-/);
  });

  it('clears req.session.user', async function () {
    session.user = {username: 'alice', is_admin: false};
    await agent.get('/ep_hash_auth/logout');
    assert.equal(session.user, undefined);
  });

  it('returns an HTML body with a link back to /', async function () {
    const res = await agent.get('/ep_hash_auth/logout');
    assert.match(res.text, /<a href="\/">/);
  });

  it('does not throw when there is no session.user to clear', async function () {
    const emptySession = {};
    const app = await buildApp(plugin, emptySession);
    const res = await supertest(app).get('/ep_hash_auth/logout');
    assert.equal(res.status, 401);
  });
});

describe('ep_hash_auth eejs blocks', function () {
  let plugin;

  // eslint-disable-next-line mocha/no-synchronous-tests
  before(function () {
    delete require.cache[require.resolve(pluginPath)];
    plugin = require(pluginPath);
  });

  const callBlock = (name) => new Promise((resolve) => {
    const args = {content: ''};
    plugin[name](name, args, () => resolve(args.content));
  });

  it('eejsBlock_userlist injects the logout button with l10n + ARIA', async function () {
    const html = await callBlock('eejsBlock_userlist');
    assert.match(html, /id="ep_hash_auth_logout_btn"/);
    assert.match(html, /data-l10n-id="ep_hash_auth\.logout"/);
    assert.match(html, /aria-label=/);
  });

  it('eejsBlock_scripts injects the client logout script', async function () {
    const html = await callBlock('eejsBlock_scripts');
    assert.match(html, /static\/plugins\/ep_hash_auth\/static\/js\/logout\.js/);
  });
});
