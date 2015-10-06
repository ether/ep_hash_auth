# ep_hash_auth

Allow the use of properly hashed passwords in [etherpad-lite]. Uses [bcrypt](https://www.npmjs.com/package/bcrypt) for password hashing and salting.

Rework of the insecure SHA2-512 password hashing which was used up to version 1.0.2.

## Usage

This plugin allows the usage of hash values for authentication in `settings.json`:

```JSON
"users": {
  "admin": {"password": "admin","is_admin": true},
  "y": {"is_admin": true, "hash": "b2112aa73994bd7cbb07732326ee102d585e706bb2e4fb878df5b5706ea92522f67b9f9dbc0208e2bd5b0f9cb21221bfb970f36a63e27e1a128ebc44d1ea5976"}
},
```

Optionally specify hash type and digest, defaults are:

```JSON
"ep_hash_auth": {
  "hash_typ": "sha512",
  "hash_dig": "hex"
},
```

## Credits

* István Király (original author)
* [LaKing](https://github.com/LaKing) (maintainer)
* [Robin `ypid` Schneider](https://github.com/ypid)

[etherpad-lite]: https://github.com/ether/etherpad-lite
