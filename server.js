'use strict';

var express = require("express");
var path = require("path");
var bodyParser = require("body-parser");
var mongodb = require("mongodb");
var crypto = require('crypto');
var getmac = require('getmac');
var ObjectID = mongodb.ObjectID;

var
  CONTACTS_COLLECTION = "contacts",
  KEYS_COLLECTION = "cryptokeys",
  ACCOUNTS_COLLECTION = "accounts";

var ALGORITHM, HMAC_ALGORITHM;
ALGORITHM = 'AES-256-CTR';
HMAC_ALGORITHM = 'SHA512';

var getMac = () => new Promise( ( resolve, reject ) =>
  getmac.getMac( ( err, address ) =>
    err ? reject( err ) : resolve( address.split( ':' ).join( '' ) )
  ));

var getDigest = ( data ) => crypto.createHash( 'sha512' ).update(
    data, 'utf8'
  ).digest( 'hex' ).toUpperCase();

var generateKeys = () => ({
  KEY      : crypto.randomBytes( 32 ).toString( 'hex' ),
  HMAC_KEY : crypto.randomBytes( 32 ).toString( 'hex' )
});

var transformKeys = ( keys ) => getMac().then( address => {
  let transformed = {
    KEY      : new Buffer( getDigest( address + keys.KEY ).substring( 0, 64 ), 'hex' ),
    HMAC_KEY : new Buffer( getDigest( keys.HMAC_KEY + process.env.HEROKU_APP_ID ).substring( 0, 64 ), 'hex' )
    /*
    KEY      : new Buffer( keys.KEY, 'hex' ),
    HMAC_KEY : new Buffer( keys.HMAC_KEY, 'hex' )
    */
  };
  console.dir( transformed );
  return transformed;
});

var getKeys = () => new Promise( ( resolve, reject ) => {
  db.collection(KEYS_COLLECTION).find().toArray( ( err, existing ) => {
    if ( err ) return reject( err );
    if ( existing.length > 0 ) {
      return resolve( transformKeys( existing[ 0 ] ) );
    }
    db.collection(KEYS_COLLECTION).insertOne( generateKeys(), (err, created) => {
      if ( err ) return reject( err );
      resolve( transformKeys( created.ops[0] ) );
    });
  });
});

var encrypt = function (plain_text) {
    var IV = new Buffer(crypto.randomBytes(16)); // ensure that the IV (initialization vector) is random
    var cipher_text;
    var hmac;
    var encryptor;

    encryptor = crypto.createCipheriv(ALGORITHM, cryptokeys.KEY, IV);
    encryptor.setEncoding('hex');
    encryptor.write(plain_text);
    encryptor.end();

    cipher_text = encryptor.read();

    hmac = crypto.createHmac(HMAC_ALGORITHM, cryptokeys.HMAC_KEY);
    hmac.update(cipher_text);
    hmac.update(IV.toString('hex')); // ensure that both the IV and the cipher-text is protected by the HMAC

    // The IV isn't a secret so it can be stored along side everything else
    return cipher_text + "$" + IV.toString('hex') + "$" + hmac.digest('hex');
};

var decrypt = function (cipher_text) {
    var cipher_blob = cipher_text.split("$");
    var ct = cipher_blob[0];
    var IV = new Buffer(cipher_blob[1], 'hex');
    var hmac = cipher_blob[2];
    var decryptor, chmac, decryptedText;

    chmac = crypto.createHmac(HMAC_ALGORITHM, cryptokeys.HMAC_KEY);
    chmac.update(ct);
    chmac.update(IV.toString('hex'));

    if (!constant_time_compare(chmac.digest('hex'), hmac)) {
        console.log("Encrypted Blob has been tampered with...");
        return null;
    }

    decryptor = crypto.createDecipheriv(ALGORITHM, cryptokeys.KEY, IV);
    decryptedText = decryptor.update(ct, 'hex', 'utf8');
    return decryptedText + decryptor.final('utf8');
};

var constant_time_compare = function (val1, val2) {
    var sentinel;

    if (val1.length !== val2.length) {
        return false;
    }


    for (var i = 0; i <= (val1.length - 1); i++) {
        sentinel |= val1.charCodeAt(i) ^ val2.charCodeAt(i);
    }

    return sentinel === 0
};



var app = express();
app.use(express.static(__dirname + "/public"));
app.use(bodyParser.json());

// Create a database variable outside of the database connection callback to reuse the connection pool in your app.
var db, cryptokeys;

var user = 'test@gmail.com';

// Connect to the database before starting the application server.
mongodb.MongoClient.connect(process.env.MONGODB_URI, function (err, database) {
  if (err) {
    console.log(err);
    process.exit(1);
  }

  // Save database object from the callback for reuse.
  db = database;
  console.log("Database connection ready");

  getKeys().then( k => {
    cryptokeys = k;

    // Initialize the app.
    var server = app.listen(process.env.PORT || 8080, function () {
      var port = server.address().port;
      console.log("App now running on port", port);
    });

    if ( ! user ) {
      db.collection(ACCOUNTS_COLLECTION).insertOne({
        user   : getDigest( 'test@gmail.com' ),
        secret : encrypt( 'FOO' )
      }, (err) => {
        if ( err ) console.log( err );
        if (!err) console.log( 'Added to accounts' );
      });
    }
    else {
      db.collection(ACCOUNTS_COLLECTION).findOne({ user : getDigest( user ) }, function(err, doc) {
        if (err) {
          console.log( err );
          return;
        }
        if (!doc) {
          console.log( 'No secret' );
          return;
        }
        console.log( decrypt(doc.secret) );
      });
    }
  }).catch( err => console.dir( err ) );
});

// CONTACTS API ROUTES BELOW

// Generic error handler used by all endpoints.
function handleError(res, reason, message, code) {
  console.log("ERROR: " + reason);
  res.status(code || 500).json({"error": message});
}

/*  "/contacts"
 *    GET: finds all contacts
 *    POST: creates a new contact
 */

app.get("/contacts", function(req, res) {
  db.collection(CONTACTS_COLLECTION).find({}).toArray(function(err, docs) {
    if (err) {
      handleError(res, err.message, "Failed to get contacts.");
    } else {
      res.status(200).json(docs);
    }
  });
});

app.post("/contacts", function(req, res) {
  var newContact = req.body;
  newContact.createDate = new Date();

  if (!(req.body.firstName || req.body.lastName)) {
    handleError(res, "Invalid user input", "Must provide a first or last name.", 400);
  }

  db.collection(CONTACTS_COLLECTION).insertOne(newContact, function(err, doc) {
    if (err) {
      handleError(res, err.message, "Failed to create new contact.");
    } else {
      res.status(201).json(doc.ops[0]);
    }
  });
});

/*  "/contacts/:id"
 *    GET: find contact by id
 *    PUT: update contact by id
 *    DELETE: deletes contact by id
 */

app.get("/contacts/:id", function(req, res) {
  db.collection(CONTACTS_COLLECTION).findOne({ _id: new ObjectID(req.params.id) }, function(err, doc) {
    if (err) {
      handleError(res, err.message, "Failed to get contact");
    } else {
      res.status(200).json(doc);
    }
  });
});

app.put("/contacts/:id", function(req, res) {
  var updateDoc = req.body;
  delete updateDoc._id;

  db.collection(CONTACTS_COLLECTION).updateOne({_id: new ObjectID(req.params.id)}, updateDoc, function(err, doc) {
    if (err) {
      handleError(res, err.message, "Failed to update contact");
    } else {
      res.status(204).end();
    }
  });
});

app.delete("/contacts/:id", function(req, res) {
  db.collection(CONTACTS_COLLECTION).deleteOne({_id: new ObjectID(req.params.id)}, function(err, result) {
    if (err) {
      handleError(res, err.message, "Failed to delete contact");
    } else {
      res.status(204).end();
    }
  });
});
