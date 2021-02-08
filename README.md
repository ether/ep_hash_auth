![Publish Status](https://github.com/ether/ep_hash_auth/workflows/Node.js%20Package/badge.svg) ![Backend Tests Status](https://github.com/ether/ep_hash_auth/workflows/Backend%20tests/badge.svg)

# ep_hash_auth

This [Etherpad](http://etherpad.org) plugin allows the usage of hashed passwords for authentication.
As of version 2.x it uses the crypto lib and/or the [bcrypt](https://www.npmjs.com/package/bcrypt) lib for comparison.
Besides settings.json, it is now possible to store the user-database in a filesystem hierarchy. The hash files are read on authentication.

```JSON
  "users": {
	"admin": {"password": "admin","is_admin": true},
	"y": {"is_admin": true, "hash": "b2112aa7399 ... b071ea5976"},
	"z": {"is_admin": true, "hash": "b5152ab7359 ... a041fa5646", "displayname": "Jane Doe"}
  }
```

optionally specify hash type and digest, folders and extension, defaults are:

```JSON
  "ep_hash_auth": {
    "hash_typ": "sha512",
    "hash_dig": "hex",
    "hash_dir": "/var/etherpad/users",
    "hash_ext": "/.hash",
    "hash_adm": false,
    "displayname_ext": "/.displayname"
  },
```
This means user Alice would have to have her hash in sha512 hex OR in bcrypt format in the following file:
```Shell
/var/etherpad/users/Alice/.hash
```
The hash_adm parameter defines the role of file-authenticated users, by default they are not admins.

The displayname_ext parameter defines from which file the displayname of a user can be read. If the file does not exist for a user, the displayname remains unchanged.

## Generate the hashes
#### Bcrypt:
```Shell
apt-get install -yqq python-bcrypt
python -c 'import bcrypt; print(bcrypt.hashpw(b"password", bcrypt.gensalt(rounds=10, prefix=b"2a")))'
```
#### Scrypt:
```Javascript
var scrypt = require('scrypt');
console.log(scrypt.kdfSync("password", scrypt.paramsSync(0.1)));
```
#### Argon2:
```Javascript
var argon2 = require('argon2');
argon2.hash("password", {timeCost: 4, memoryCost: 2 ** 13, parallelism: 2, type: argon2.argon2i}).then(hash => {console.log(hash);});
```

## Credits

* István Király [LaKing](https://github.com/LaKing) (author and maintainer)
* [Robin `ypid` Schneider](https://github.com/ypid) (contributor)
* [id01](https://github.com/id01) (contributor)

## the [npm](https://www.npmjs.com/package/ep_hash_auth)
