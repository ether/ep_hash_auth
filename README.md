This plugin allows the usage of hash values for authentoication in settings.json

  "users": {
	"admin": {"password": "admin","is_admin": true},
	"y": {"is_admin": true, "hash": "b2112aa73994bd7cbb07732326ee102d585e706bb2e4fb878df5b5706ea92522f67b9f9dbc0208e2bd5b0f9cb21221bfb970f36a63e27e1a128ebc44d1ea5976"}
  }

optionally specify hash type and digest, defaults are:

  "ep_hash_auth": {
    "hash_typ": "sha512",
    "hash_dig": "hex"
  },
  
