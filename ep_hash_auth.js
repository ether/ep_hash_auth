/* hash based authentication for etherpad
 * 2014 - István Király - LaKing@D250.hu
 * Reworked by Robin Schneider <ypid@riseup.net> to allow the use of proper password hash algorithms.
 */

var settings = require('ep_etherpad-lite/node/utils/Settings');
var authorManager = require('ep_etherpad-lite/node/db/AuthorManager');
var bcrypt = require('bcrypt');

exports.authenticate = function(hook_name, context, cb) {
  // console.debug('ep_hash_auth.authenticate');
  // console.log(context.req.headers.authorization);

  if (context.req.headers.authorization && context.req.headers.authorization.search('Basic ') === 0) {
    var userpass = new Buffer(context.req.headers.authorization.split(' ')[1], 'base64').toString().split(":")
      var username = userpass.shift();
    var password = userpass.join(':');
    // console.log(username);
    // console.log(password);

    // Authenticate user via settings.json
    if (settings.users[username] != undefined) {
      // hash defined in "hash" of users
      if (settings.users[username].hash != undefined) {
        if (bcrypt.compareSync(password, settings.users[username].hash)) {
          settings.users[username].username = username;
          context.req.session.user = settings.users[username];
          return cb([true]);
        }
      }
    }
  }
  return cb([false]);
};
