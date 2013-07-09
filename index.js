var resource = require('resource'),
    logger = resource.logger,
    http = resource.use('http'),
    config = resource.use('config'),
    auth = resource.use('auth'),
    user = resource.use('user'),
    google = resource.define('auth-google-oauth');

google.schema.description = "for integrating google oauth authentication";

google.persist('memory');

// .start() convention
function start(options, callback) {
  var async = require('async');
  //
  // setup auth provider
  //
  async.parallel([
    // setup .view convention
    function(callback) {
      var view = resource.use('view');
      view.create({ path: __dirname + '/view' }, function(err, _view) {
          if (err) { return callback(err); }
          google.view = _view;
          return callback(null);
      });
    },
    // start auth with google
    function(callback) {
      auth.start({provider: google}, callback);
    },
    // use auth strategy of provider
    function(callback) {
      google.strategy(function(err, strategy) {
        if (err) { return callback(err); }
        auth.use(strategy, callback);
      });
    },
    // use route of provider
    function(callback) {
      google.routes({}, callback);
    }],
  function(err, results) {
    return callback(err);
  });
}
google.method('start', start, {
  description: "starts google"
});

google.property('credentials', {
  description: 'google credentials',
  type: 'object',
  properties: {
    accessToken: {
      description: 'access token of google auth',
      type: 'string',
      required: true
    },
    refreshToken: {
      description: 'refresh token of google auth',
      type: 'string',
      required: false
    }
  }
});

google.property('profile', {
  description: 'profile of google auth'
});

function strategy(callback) {
  var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy,
      async = require('async');
  // Use the GoogleStrategy within Passport.
  //   Strategies in Passport require a `verify` function, which accept
  //   credentials (in this case, an accessToken, refreshToken, and google
  //   profile), and invoke a callback with a user object.
  return callback(null, new GoogleStrategy({
    clientID: config['auth-google-oauth'].clientID,
    clientSecret: config['auth-google-oauth'].clientSecret,
    callbackURL: "http://localhost:8888/auth/google/callback",
    passReqToCallback: true
  },
  function(req, accessToken, refreshToken, profile, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
      async.waterfall([
        // get google instance, or create if not already exist
        function(callback) {
          google.get(profile.id, function(err, _google) {
            if (err && (err.message === profile.id + " not found")) {
              logger.info("google id", profile.id, "not found. creating new google");
              google.create({
                id: profile.id,
                credentials: {
                  accessToken: accessToken,
                  refreshToken: refreshToken
                },
                profile: profile
              }, callback);
            } else if (err) {
              return callback(err);
            } else {
              logger.info("google id ", _google.id, "found");
              google.update({
                id: profile.id,
                credentials: {
                  accessToken: accessToken,
                  refreshToken: refreshToken
                },
                profile: profile
              }, callback);
            }
          });
        },
        // log google object
        function(_google, callback) {
          logger.info("google object", JSON.stringify(_google));
          return callback(null, _google);
        },
        // associate google with user auth
        function(_google, callback) {
          var _user = req.user;
          if (!_user) {
            logger.info('user is not logged in');
            async.waterfall([
              // find auth instances with google id, or create none exist
              function(callback) {
                auth.find({'google-oauth': _google.id}, function(err, _auths) {
                  if (err) { return callback(err); }
                  else if (_auths.length > 1) {
                    logger.info("multiple auths with same google id found!");
                    // TODO merge multiple auths with same google into one
                    return callback(null, _auth[0]);
                  } else if (_auths.length === 0) {
                    logger.info("google id", _google.id, "not found in any auth. creating new auth");
                    auth.create({google: _google.id}, callback);
                  } else {
                    logger.info("using existing auth", _auths[0].id);
                    return callback(null, _auths[0]);
                  }
                });
              },
              // log auth object
              function(_auth, callback) {
                logger.info("auth object", JSON.stringify(_auth));
                return callback(null, _auth);
              },
              // find user instance with auth id, or create if none exist
              function(_auth, callback) {
                logger.info("getting user with auth id");
                user.get(_auth.id, function(err, _user) {
                  if (err && (err.message === _auth.id + " not found")) {
                    logger.info("user id", _auth.id, "not found. creating new user");
                    user.create({id: _auth.id}, callback);
                  } else if (err) {
                    return callback(err);
                  } else {
                    logger.info("user id ", _user.id, "found");
                    return callback(null, _user);
                  }
                });
              }],
              // return user object to top waterfall
              callback);
          } else {
            logger.info('user is logged in');
            auth.get(_user.id, function(err, _auth) {
              // TODO check for collisions here
              // associate google with auth
              _auth['google-oauth'] = _google.id;
              // save auth instance
              _auth.save(function(err, _auth) {
                if (err) { return callback(err); }
                // log auth object
                logger.info("auth object", JSON.stringify(_auth));
                // return user object to top waterfall
                return callback(null, _user);
              });
            });
          }
        }],
        // end top waterfall
        done);
    });
  }));
}
google.method('strategy', strategy, {
  description: 'return google strategy'
});

function routes(options, callback) {
  // GET /auth/google
  // Use passport.authenticate() as route middleware to authenticate the
  // request. The first step in Google authentication will involve
  // redirecting the user to google.com. After authorization, Google
  // will redirect the user back to this application at /auth/google/callback
  http.app.get('/auth/google',
    auth.authenticate('google', { scope: ['https://www.googleapis.com/auth/userinfo.profile',
                                           'https://www.googleapis.com/auth/userinfo.email'] }),
    function (req, res) {
      // The request will be redirected to Google for authentication, so this
      // function will not be called.
    });
  // GET /auth/google/callback
  // Use passport.authenticate() as route middleware to authenticate the
  // request. If authentication fails, the user will be redirected back to the
  // login page. Otherwise, the primary route function function will be called,
  // which, in this example, will redirect the user to the home page.
  http.app.get('/auth/google/callback',
    auth.authenticate('google', { failureRedirect: '/' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/');
    });
  return callback(null);
}
google.method('routes', routes, {
  description: 'sets routes for google in app'
});

google.dependencies = {
  'passport-google-oauth': '*'
};
google.license = 'MIT';
exports['auth-google-oauth'] = google;
