(function() {

  var crypto = require('crypto');
  var _ = require('underscore');
  var dotty = require('dotty');
  var async = require('async');

  var AGGREGATED_ALGORITHM = 'aes-256-cbc';
  var IV_LENGTH = 16;
  var SEPARETED_ALGORITHM = 'rc4';

  var isEmbeddedDocument = function(doc) {
    return doc.constructor.name === 'EmbeddedDocument';
  };

  var getSEncryptFn = function (key) {
    return function(value, done) {
      var cipher = crypto.createCipher(SEPARETED_ALGORITHM, key);
      cipher.end(JSON.stringify(value), 'utf8', function() {
        done(null, cipher.read());
      });
    };
  }

  var getSDecryptFn = function (key) {
    return function(cipher) {
      var decipher = crypto.createDecipher(SEPARETED_ALGORITHM, new Buffer(key));
      var decryptedObjJSON = decipher.update(new Buffer(cipher, 'base64'), undefined, 'utf8') + decipher.final('utf8');
      try {
        return JSON.parse(decryptedObjJSON);
      } catch (err) {
        throw new Error('Error parsing JSON during separated decrypt: ' + err);
      }
    };
  }

  var getAEncryptFn = function (key) {
    return function(value, done) {
      crypto.randomBytes(IV_LENGTH, function(err, iv) {
          if (err) {return done(err); }

          var cipher = crypto.createCipheriv(AGGREGATED_ALGORITHM, key, iv);
          cipher.end(JSON.stringify(value), 'utf8', function() {
            var encryptedData = Buffer.concat([iv, cipher.read()]);
            done(null, encryptedData);
          });
      });
    };
  }

  var getADecryptFn = function (key) {
    return function (encryptedData) {
      var encryptedDataWithIV = encryptedData.buffer || encryptedData;
      var iv = encryptedDataWithIV.slice(0, IV_LENGTH);
      var encryptedData = encryptedDataWithIV.slice(IV_LENGTH, encryptedDataWithIV.length);
      var decipher = crypto.createDecipheriv(AGGREGATED_ALGORITHM, key, iv);

      var decryptedObjJSON = decipher.update(encryptedData, undefined, 'utf8') + decipher.final('utf8');
      try {
        return JSON.parse(decryptedObjJSON);
      } catch (err) {
        throw new Error('Error parsing JSON during aggregation decrypt: ' + err);
      }
    }
  }

  // var encryptSeparatedField = function(fieldName, done) {
  //   var that = this;
  //   var fieldValue = that[fieldName];
  //   if (fieldValue === undefined) {return done(null); }

  //   _separetedEncrypt(JSON.stringify(fieldValue), function(err, encryptedFieldValue) {
  //     if (err) {return done(err);}
  //     console.log('MODEL pre', that[fieldName], encryptedFieldValue.toString('base64'))
  //     that[fieldName] = encryptedFieldValue.toString('base64');
  //     console.log('MODEL post', that[fieldName])
  //     done(null);
  //   });
  // };


  module.exports = function(schema, options) {

    // Preparation

    //
    // Separated encryption (SE)
    //

    var optionsSE = options.separated

    if (!optionsSE.key) {
      throw new Error('options.separated.key is required as a base64 string');
    }

    var keySE = new Buffer(optionsSE.key, 'base64');
    var fieldsSE = [];


    //
    // Aggregated encryption (AE)
    //

    var optionsAE = options.aggregated

    if (!optionsAE.key) {
      throw new Error('options.aggregated.key is required as a 32 byte base64 string');
    }

    var keyAE = new Buffer(optionsAE.key, 'base64');
    var fieldsAE = [];

    // Add cypher text path to schema
    if (!schema.paths._ct) {
      schema.add({ _ct: {type: Buffer}});
    }

    // Analyze schema and fill SE and AE field arrays

    for (var path in schema.paths) {
      var details = schema.paths[path];
      // If indexed field - encryption impossible
      var encrypt = details.options.encrypt;
      if (typeof details.options.type[0] === 'object') {
        encrypt = details.options.type[0].encrypt;
      }
      if (!details._index && encrypt) {
        (encrypt === 'aggregated') ? fieldsAE.push(path) : fieldsSE.push(path);
      }
    }


    // Extend scheme methods

    schema.methods.encrypt = function(done) {
      var doc = this;
      var encrypts = [];
      if (fieldsSE.length) {
        encrypts.push(doc.encryptSE.bind(doc));
      }
      if (fieldsAE.length) {
        encrypts.push(doc.encryptAE.bind(doc));
      }
      async.parallel(encrypts, function(err, result) {
        done(err);
      });
    };

    schema.methods.decrypt = function(done) { // callback style but actually synchronous to allow for decryptSync without copypasta or complication
      try {
        schema.methods.decryptSync.call(this);
      } catch(e){
        return done(e);
      }
      done();
    };

    schema.methods.decryptSync = function() {
      var doc = this;
      if (doc._co) {
        schema.methods.decryptSE.call(doc);
        doc._co = undefined;
      }
      if (doc._ct) {
        schema.methods.decryptAE.call(doc);
        doc._ct = undefined;
      }
      return doc;
    };


    // Extend scheme if exists SE fields
    if (fieldsSE.length) {

      // Add cypher object path to schema
      if (!schema.paths._co) {
        schema.add({ _co: {type: 'Mixed'}});
      }

      var encryptSE = getSEncryptFn(keySE);

      // Add encrypt method for SE
      schema.methods.encryptSE = function (done) {
        var doc = this;
        async.each(fieldsSE, function (fieldName, cb) {
          var val = doc[fieldName];
          if (val === undefined) { return cb(null); }
          encryptSE(val, function (err, encryptedValue) {
            if (err) { return cb(err); }
            doc[fieldName] = undefined;
            doc._co[fieldName] = encryptedValue;
            cb(null);
          })
        }, done);
      }

      var decryptSE = getSDecryptFn(keySE);

      // Add decrypt method for SE, should be synchronous
      schema.methods.decryptSE = function () {
        var doc = this;
        var cipherObj = doc._co;
        for (var field in cipherObj) {
          doc[field] = decryptSE(cipherObj[field]);
        }
      }
    }

    // Extend scheme if exists AE fields
    if (fieldsAE.length) {

      // Add cypher text path to schema
      if (!schema.paths._ct) {
        schema.add({ _ct: {type: Buffer}});
      }

      var encryptAE = getAEncryptFn(keyAE);

      // Add encrypt method for AE
      schema.methods.encryptAE = function (done) {
        var doc = this;
        var objectToEncrypt = {};
        _.each(fieldsAE, function (fieldName) {
          var val = doc[fieldName];
          if (val !== undefined) {
            objectToEncrypt[fieldName] = val;
            doc[fieldName] = undefined;
          }
        })
        encryptAE(objectToEncrypt, function (err, encryptedData) {
          if (err) { return done(err); }
          doc._ct = encryptedData;
          done(null);
        })
      }

      var decryptAE = getADecryptFn(keyAE);

      // Add decrypt method for AE, should be synchronous
      schema.methods.decryptAE = function () {
        var doc = this;

        var decryptedObject = decryptAE(doc._ct);
        for (var field in decryptedObject) {
          doc[field] = decryptedObject[field];
        }
      }

    }


    // Add hooks

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
