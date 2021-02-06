'use strict';

// 2.x hash based authentication for etherpad
// 2014-2016 - István Király - LaKing@D250.hu
// Contributions by Robin Schneider <ypid@riseup.net>
// Contributions by id01 <https://github.com/id01>

// Made on codepad :P

const fs = require('fs');
const settings = require('ep_etherpad-lite/node/utils/Settings');
const authorManager = require('ep_etherpad-lite/node/db/AuthorManager');
const crypto = require('crypto');

// npm install bcrypt/scrypt/argon2 (optional but recommended)
const optionalRequire = (library, name, npmLibrary) => {
  try {
    return require(library);
  } catch (e) {
    console.log(`Note: ${library} library could not be found. ${name} support will be disabled.`);
    if (npmLibrary) {
      console.log(`Run "npm install ${npmLibrary}" to enable ${name}`);
    }
  }
};

const bcrypt = optionalRequire('bcrypt', 'bcrypt', 'bcrypt');
const scrypt = optionalRequire('scrypt', 'scrypt', 'scrypt');
const argon2 = optionalRequire('argon2', 'argon2', 'argon2');

// ocrypt-relevant options
let hash_typ = 'sha512';
let hash_dig = 'hex';

// default dir to search for hash files
let hash_dir = '/var/etherpad/users';
// by default the extension is actually a file, so usernames are actually folders
let hash_ext = '/.hash';
// by default peple logged in that authenticated over a hash file, are admins?
let hash_adm = false;
// default filename containing the displayname of a user
let displayname_ext = '/.displayname';


if (settings.ep_hash_auth) {
  if (settings.ep_hash_auth.hash_typ) hash_typ = settings.ep_hash_auth.hash_typ;
  if (settings.ep_hash_auth.hash_dig) hash_dig = settings.ep_hash_auth.hash_dig;
  if (settings.ep_hash_auth.hash_dir) hash_dir = settings.ep_hash_auth.hash_dir;
  if (settings.ep_hash_auth.hash_ext) hash_ext = settings.ep_hash_auth.hash_ext;
  if (settings.ep_hash_auth.hash_adm) hash_adm = settings.ep_hash_auth.hash_adm;
  if (settings.ep_hash_auth.displayname_ext) {
    displayname_ext = settings.ep_hash_auth.displayname_ext;
  }
}

// Let's make a function to compare our hashes now that we have multiple comparisons required.
// This function calls callback(hashType) if authenticated, or callback(null) if not.
const compareHashes = async (password, hash, callback) => {
  const cryptoHash = crypto.createHash(hash_typ).update(password).digest(hash_dig);

  if (hash === cryptoHash) { // Check whether this is a crypto hash first
    return callback('crypto');
    // If not, check other hash types
  } else if (hash[0] === '$') {
    // This is an argon2 or bcrypt hash
    if (hash.slice(0, 7) === '$argon2') {
      // This is argon2
      if (argon2) {
        if (await argon2.verify(hash, password)) {
          return callback('argon2');
        } else {
          return callback(null);
        }
      } else {
        console.log('Warning: Could not verify argon2 hash due to missing dependency');
      }
    } else if (bcrypt) {
      if (await bcrypt.compare(password, hash)) {
        return callback('bcrypt');
      } else {
        return callback(null);
      }
    } else {
      console.log('Warning: Could not verify bcrypt hash due to missing dependency');
    }
  } else if (scrypt) {
    // This is a scrypt hash or a failed crypto hash
    if (scrypt.verifyKdfSync(Buffer.from(hash, 'hex'), Buffer.from(password))) {
      return callback('scrypt');
    } else {
      return callback(null);
    }
  } else {
    console.log('Warning: Could not verify scrypt hash due to missing dependency');
  }
  return callback(null);
};

exports.authenticate = (hook_name, context, cb) => {
  if (context.req.headers.authorization &&
      context.req.headers.authorization.search('Basic ') === 0) {
    const userpass = Buffer.from(
        context.req.headers.authorization.split(' ')[1], 'base64').toString().split(':');
    const username = userpass.shift();
    const password = userpass.join(':');

    // Authenticate user via settings.json
    if (settings.users[username] !== undefined && settings.users[username].hash !== undefined) {
      compareHashes(password, settings.users[username].hash, (hashType) => {
        if (hashType) {
          console.log(`Log: Authenticated (${hashType}) ${username}`);
          settings.users[username].username = username;
          context.req.session.user = settings.users[username];
          // use displayname if available
          if (settings.users[username].displayname !== undefined) {
            context.req.session.user.displayname = settings.users[username].displayname;
          } else {
            console.log(`Log: displayname not found for user ${username}`);
          }
          return cb([true]);
        } else { return cb([false]); }
      });
    } else {
      // Authenticate user via hash_dir
      const path = `${hash_dir}/${username}${hash_ext}`;
      fs.readFile(path, 'utf8', (err, contents) => {
        if (err) {
          // file not found, or inaccessible
          console.log(
              `Error: Failed authentication attempt for ${username}: no authentication found`);
          return cb([false]);
        } else {
          compareHashes(password, contents, (hashType) => {
            if (hashType) {
              console.log(`Log: Authenticated (${hashType}-file) ${username}`);
              // read displayname if available
              const displaynamepath = `${hash_dir}/${username}${displayname_ext}`;
              fs.readFile(displaynamepath, 'utf8', (err, contents) => {
                let displayname;
                if (err) {
                  console.log(`Log: Could not load displayname for ${username}`);
                } else {
                  displayname = contents;
                }
                settings.users[username] = {username, is_admin: hash_adm, displayname};
                context.req.session.user = settings.users[username];
                return cb([true]);
              });
            } else { return cb([false]); }
          });
        }
      });
    }
  } else { return cb([false]); }
};

exports.handleMessage = (hook_name, context, cb) => {
  // skip if we don't have any information to set
  const session = context.client.client.request.session;
  if (!session || !session.user || !session.user.displayname) return cb();

  authorManager.getAuthor4Token(context.message.token).then((author) => {
    authorManager.setAuthorName(author, context.client.client.request.session.user.displayname);
    cb();
  }).catch((error) => {
    console.error(
        'handleMessage: could not get authorid for token %s', context.message.token, error);
    cb();
  });
};
