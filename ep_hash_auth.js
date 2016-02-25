// 2.x hash based authentication for etherpad
// 2014-2016 - István Király - LaKing@D250.hu
// Contributions by Robin Schneider <ypid@riseup.net>

// Made on codepad :P

var fs = require('fs');
var settings = require('ep_etherpad-lite/node/utils/Settings');
var authorManager = require('ep_etherpad-lite/node/db/AuthorManager');
var sessionManager = require('ep_etherpad-lite/node/db/SessionManager');
var crypto = require('crypto');

// npm install bcrypt
var bcrypt = require('bcrypt');

// ocrypt-relevant options
var hash_typ = "sha512";
var hash_dig = "hex";

// default dir to search for hash files
var hash_dir = '/var/etherpad/users';
// by default the extension is actually a file, so usernames are actually folders
var hash_ext = '/.hash';
// by default peple logged in that authenticated over a hash file, are admins?
var hash_adm = false;


if (settings.ep_hash_auth) {
    if (settings.ep_hash_auth.hash_typ) hash_typ = settings.ep_hash_auth.hash_typ;
    if (settings.ep_hash_auth.hash_dig) hash_dig = settings.ep_hash_auth.hash_dig;
    if (settings.ep_hash_auth.hash_dir) hash_dir = settings.ep_hash_auth.hash_dir;
    if (settings.ep_hash_auth.hash_ext) hash_ext = settings.ep_hash_auth.hash_ext;
    if (settings.ep_hash_auth.hash_adm) hash_adm = settings.ep_hash_auth.hash_adm;
}

exports.authenticate = function(hook_name, context, cb) {
    if (context.req.headers.authorization && context.req.headers.authorization.search('Basic ') === 0) {
        var userpass = new Buffer(context.req.headers.authorization.split(' ')[1], 'base64').toString().split(":");
        var username = userpass.shift();
        var password = userpass.join(':');

        var hash = crypto.createHash(hash_typ).update(password).digest(hash_dig);

        // Authenticate user via settings.json
        if (settings.users[username] !== undefined) {
            // hash defined in "hash" of users
            if (settings.users[username].hash !== undefined) {
                if (settings.users[username].hash == hash) {
                    console.log("Authenticated (crypto) " + username);
                    settings.users[username].username = username;
                    context.req.session.user = settings.users[username];
                    return cb([true]);
                } else {
                    bcrypt.compare(password, settings.users[username].hash, function(err, res) {
                        if (err || !res) return cb([false]);
                        else {
                            console.log("Authenticated (bcrypt) " + username);
                            settings.users[username].username = username;
                            context.req.session.user = settings.users[username];
                            return cb([true]);
                        }
                    });
                }
            } else return cb([false]);

        } else {
            // Authenticate user via hash_dir
            var path = hash_dir + "/" + username + hash_ext;
            fs.readFile(path, 'utf8', function(err, contents) {
                if (err) {
                    // file not found, or inaccessible
                    console.log("AUTH: cannot authenticate " + username);
                    return cb([false]);
                } else {
                    if (contents === hash) {
                        console.log("Authenticated (crypto-file) " + username);
                        settings.users[username] = {};
                        settings.users[username].username = username;
                        settings.users[username].is_admin = hash_adm;
                        context.req.session.user = settings.users[username];
                        return cb([true]);
                    } else {
                        bcrypt.compare(password, contents, function(err, res) {
                            if (err || !res) return cb([false]);
                            else {
                                console.log("Authenticated (bcrypt-file) " + username);
                                settings.users[username] = {};
                                settings.users[username].username = username;
                                settings.users[username].is_admin = hash_adm;
                                context.req.session.user = settings.users[username];
                                return cb([true]);
                            }
                        });
                    }
                }
            });
        }
    } else return cb([false]);

};

// 1.0.2 version archived
// hash based authentication for etherpad
// 2014 - István Király - LaKing@D250.hu
/*
var settings = require('ep_etherpad-lite/node/utils/Settings');
var authorManager = require('ep_etherpad-lite/node/db/AuthorManager');
var crypto = require('crypto');

var hash_typ = "sha512";
var hash_dig = "hex";

if (settings.ep_hash_auth) {
    if (settings.ep_hash_auth.hash_typ) hash_typ = settings.ep_hash_auth.hash_typ;
    if (settings.ep_hash_auth.hash_dig) hash_dig = settings.ep_hash_auth.hash_dig;
}

exports.authenticate = function(hook_name, context, cb) {
  console.debug('ep_hash_auth.authenticate');

  if (context.req.headers.authorization && context.req.headers.authorization.search('Basic ') === 0) {
    var userpass = new Buffer(context.req.headers.authorization.split(' ')[1], 'base64').toString().split(":")
    var username = userpass.shift();
    var password = userpass.join(':');
    var hash = crypto.createHash(hash_typ).update(password).digest(hash_dig);

    // Authenticate user via settings.json
    if (settings.users[username] != undefined) {
      // hash defined in "hash" of users
      if (settings.users[username].hash != undefined) {
        if (settings.users[username].hash == hash) {
          settings.users[username].username = username;
          context.req.session.user = settings.users[username];
          return cb([true]);
        }
      }
    }
  }
  return cb([false]);
};
*/