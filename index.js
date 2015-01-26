(function() {

  var crypto = require('crypto');
  var _ = require('underscore');
  var dotty = require('dotty');
  var async = require('async');

  var ALGORITHM = 'aes-256-cbc';
  var SIMPLE_ALGORITHM = 'rc4';
  var IV_LENGTH = 16;

  var isEmbeddedDocument = function(doc) {
    return doc.constructor.name === 'EmbeddedDocument';
  };

  module.exports = function(schema, options) {

    var details, separateEncryptedFields, encryptedFields, excludedFields;

    if (!options.key)
      throw new Error('options.key is required as a 32 byte base64 string');
    if (!options.simpleKey)
      throw new Error('options.simpleKey is required as a base64 string');

    var key = new Buffer(options.key, 'base64');
    var simpleKey = new Buffer(options.simpleKey, 'base64');

    if (!schema.paths._ct)
      schema.add({
        _ct: {
          type: Buffer
        }
      });

    if (options.fields)
      encryptedFields = _.difference(options.fields, ['_ct']);
    else {
      excludedFields = _.union(['_id', '_ct'], options.exclude);
      encryptedFields = [];
      for (var path in schema.paths) {
        details = schema.paths[path];
        if (excludedFields.indexOf(path) < 0 && !details._index) {
          encryptedFields.push(path);
        }
      }
    }

    // fill separate encrypted fields arr
    separateEncryptedFields = [];
    for (var path in schema.paths) {
      details = schema.paths[path];
      if (details.options.encrypt) {
        separateEncryptedFields.push(path);
      }
    }
    // TODO: make optimization of arrays filling
    encryptedFields = _.difference(encryptedFields, separateEncryptedFields);

    schema.pre('init', function(next, data) {
      if (isEmbeddedDocument(this)) {
        this.decryptSync.call(data);
        this._doc = data;
        return this; // must return updated doc synchronously for EmbeddedDocuments
      } else {
        this.decrypt.call(data, function(err){
          if (err)
            throw new Error(err); // throw because passing the error to next() in this hook causes it to get swallowed
          next();
        });
      }
    });

    schema.pre('save', function(next) {
      if (this.isNew || this.isSelected('_ct'))
        this.encrypt(next);
      else
        next();
    });

    decryptEmbeddedDocs = function(doc) {
      _.keys(doc.schema.paths).forEach(function(path) {
        if (path === '_id' || path === '__v') return;

        var nestedDoc = dotty.get(doc, path);

        if (nestedDoc && nestedDoc[0] && isEmbeddedDocument(nestedDoc[0])) {
          nestedDoc.forEach(function(subDoc) {
            if (_.isFunction(subDoc.decryptSync)) subDoc.decryptSync();
          });
        }
      });
    };

    schema.post('save', function(doc) {
      if (_.isFunction(doc.decryptSync)) doc.decryptSync();

      // Until 3.8.6, Mongoose didn't trigger post save hook on EmbeddedDocuments,
      // instead had to call decrypt on all subDocs.
      // ref https://github.com/LearnBoost/mongoose/issues/915

      decryptEmbeddedDocs(doc);

      return doc;
    });


    var _lightEncrypt = function(value, done) {
      var cipher = crypto.createCipher(SIMPLE_ALGORITHM, simpleKey);
      cipher.end(value, 'utf8', function() {
        done(null, cipher.read());
      });
    };

    var _hardEncrypt = function(value, done) {
      crypto.randomBytes(IV_LENGTH, function(err, iv) {
          if (err) {return done(err); }

          var cipher = crypto.createCipheriv(ALGORITHM, key, iv);
          cipher.end(value, 'utf8', function() {
            done(null, cipher.read(), iv);
          });
      });

    };

    var encryptSeparatedField = function(fieldName, done) {
      var that = this;
      var fieldValue = that[fieldName];
      if (fieldValue === undefined) {return done(null); }

      _lightEncrypt(JSON.stringify(fieldValue), function(err, encryptedFieldValue) {
        if (err) {return done(err);}
        console.log('MODEL pre', that[fieldName], encryptedFieldValue.toString('base64'))
        that[fieldName] = encryptedFieldValue.toString('base64');
        console.log('MODEL post', that[fieldName])
        done(null);
      });
    };

    var decryptSeparatedValue = function(value) {
      var decipher, decryptedObjectJSON, decryptedObject;
      // console.log('DECRYPT', value)
      if (typeof value !== 'string') { return value; }
      decipher = crypto.createDecipher(SIMPLE_ALGORITHM, new Buffer(simpleKey));
      decryptedObjectJSON = decipher.update(new Buffer(value, 'base64'), undefined, 'utf8') + decipher.final('utf8');
      try {
        return JSON.parse(decryptedObjectJSON);
      } catch (err) {
        throw new Error('Error parsing JSON during decrypt: ' + err);
      }
    };

    schema.methods.encrypt = function(done) {
      var that = this;
      async.parallel({
        encrypt: function (cb) {
          var field, val;
          var objectToEncrypt = _.pick(that, encryptedFields);
          for (field in objectToEncrypt) {
            val = objectToEncrypt[field];
            if (val === undefined) {
              delete objectToEncrypt[field];
            } else {
              that[field] = undefined;
            }
          }
          _hardEncrypt(JSON.stringify(objectToEncrypt), function (err, encryptedData, iv) {
            if (err) {return cb(err);}
            that._ct = Buffer.concat([iv, encryptedData]);
            cb(null);
          });
        },
        encryptSeparated: function (cb) {
          async.each(separateEncryptedFields, encryptSeparatedField.bind(that), cb);
        },
      }, function(err, result) {
        done(err);
      });
    };

    schema.methods.decrypt = function(cb) { // callback style but actually synchronous to allow for decryptSync without copypasta or complication
      try {
        schema.methods.decryptSync.call(this);
      } catch(e){
        return cb(e);
      }
      cb();
    };


    schema.methods.decryptSync = function() {
      var ct, ctWithIV, decipher, iv, decryptedObjectJSON, decryptedObject;
      if (this._ct) {
        ctWithIV = this._ct.buffer || this._ct;
        iv = ctWithIV.slice(0, IV_LENGTH);
        ct = ctWithIV.slice(IV_LENGTH, ctWithIV.length);
        decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decryptedObjectJSON = decipher.update(ct, undefined, 'utf8') + decipher.final('utf8');
        try {
          decryptedObject = JSON.parse(decryptedObjectJSON);
        } catch (err) {
          if (this._id)
            idString = this._id.toString();
          else
            idString = 'unknown';
          throw new Error('Error parsing JSON during decrypt of ' + idString + ': ' + err);
        }
        for (var field in decryptedObject) {
          decipheredVal = decryptedObject[field];
          this[field] = decipheredVal;
        }
        var that = this;
        _.each(separateEncryptedFields, function(fieldName) {
          that[fieldName] = decryptSeparatedValue(that[fieldName]);
        });
        this._ct = undefined;
      }


    };
  };

  // applied to schemas that contain encrypted embedded documents
  // this ensures that if parent has a validation error, children don't come out encrypted,
  // which could otherwise cause data loss if validation error fixed and a resave was attempted
  module.exports.encryptedChildren = function(schema, options) {
    schema.post('validate', function(doc) {
      if (doc.errors) {
        decryptEmbeddedDocs(doc);
      }
    });
  };

}).call(this);
