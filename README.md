# ep_hash_auth

This [etherpad-lite](http://etherpad.org) plugin allows the usage of hashed passwords for authentication.
As of version 2.x it uses the crypto lib and/or the [bcrypt](https://www.npmjs.com/package/bcrypt) lib for comparison.
Besides settings.json, it is now possible to store the user-database in a filesystem hierarchy. The hash files are read on authentication.

```JSON
  "users": {
	"admin": {"password": "admin","is_admin": true},
	"y": {"is_admin": true, "hash": "b2112aa7399 ... b071ea5976"}
  }
```

optionally specify hash type and digest, folders and extension, defaults are:

```JSON
  "ep_hash_auth": {
    "hash_typ": "sha512",
    "hash_dig": "hex",
    "hash_dir": "/var/etherpad/users",
    "hash_ext": "/.hash",
    "hash_adm": false
  },
```
This means user Alice would have to have her hash in sha512 hex OR in bcrypt format in the following file:
```Shell
/var/etherpad/users/Alice/.hash
```
The hash_adm parameter defines the role of file-authenticated users, by default they are not admins.

## Generate the hashes
```Shell
apt-get install -yqq python-bcrypt
python -c 'import bcrypt; print(bcrypt.hashpw(b"password", bcrypt.gensalt(rounds=10, prefix=b"2a")))'
```

## Credits

* István Király [LaKing](https://github.com/LaKing) (author and maintainer)
* [Robin `ypid` Schneider](https://github.com/ypid) (contributor)

## the [npm](https://www.npmjs.com/package/ep_hash_auth)
