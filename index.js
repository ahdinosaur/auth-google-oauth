var resource = require('resource'),
    logger = resource.logger,
    http = resource.use('http'),
    config = resource.use('config')['auth-google-oauth'],
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
  callback(null, new GoogleStrategy({
    clientID: config.clientID,
    clientSecret: config.clientSecret,
    callbackURL: "http://localhost:8888/auth/google/callback",
    passReqToCallback: true
  },
  function(req, accessToken, refreshToken, profile, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
      if (!req.user) {
        logger.info('user is not logged in, authorizing with google');
        async.waterfall([
          // get google instance
          function(callback) {
            google.get(profile.id, function(err, _google) {
              if (err && (err.message === profile.id + " not found")) {
                logger.info("profile.id not found. creating new google");
                google.create({
                  id: profile.id,
                  credentials: {
                    accessToken: accessToken,
                    refreshToken: refreshToken
                  },
                  profile: profile
                }, function(err, _google) {
                  if (err) { return callback(err); }
                  logger.info("new google with id", _google.id, "created");
                  logger.info("new google object", JSON.stringify(_google));
                  return callback(null, _google);
                });
              } else if (err) {
                return callback(err);
              } else {
                logger.info("profile.id found, updating google info");
                google.update({
                  id: profile.id,
                  credentials: {
                    accessToken: accessToken,
                    refreshToken: refreshToken
                  },
                  profile: profile
                }, function(err, _google) {
                  if (err) { return callback(err); }
                  return callback(null, _google);
                });
              }
            });
          },
          // get user instance
          function(_google, callback) {
            logger.info("finding user with google profile.id");
            user.find({'google-oauth': _google.id}, function(err, _users) {
              if (err) { return callback(err); }
              else if (_users.length > 1) {
                logger.info("multiple users with same google id found!");
                // TODO merge multiple users with same google into one
                return callback(null, _user[0]);
              } else if (_users.length === 0) {
                logger.info("user not found, creating new user");
                user.create({'google-oauth': _google.id}, function(err, _user) {
                  if (err) { return callback(err); }
                  logger.info("new user with id", _user.id, "created");
                  logger.info("new user object", JSON.stringify(_user));
                  return callback(null, _user);
                });
              } else {
                logger.info("using existing user", _users[0].id);
                return callback(null, _users[0]);
              }
            });
          }],
          // return user as auth
          function(err, _user) {
            if (err) { return done(err); }
            return done(null, _user);
          });
      } else {
        logger.info('user is logged in, associating google with user');
        var _user = req.user;
        google.get(profile.id, function(err, _google) {
          if (err && (err.message === profile.id + " not found")) {
            logger.info("profile.id not found. creating new google");
            google.create({
              id: profile.id,
              credentials: {
                accessToken: accessToken,
                refreshToken: refreshToken
              },
              profile: profile
            }, function(err, _google) {
              if (err) { return done(err); }
              logger.info("new google with id", _google.id, "created");
              logger.info("new google object", JSON.stringify(_google));
              // associate new google with user
              _user['google-oauth'] = _google.id;
              // preserve the login state by returning the existing user
              _user.save(done);
            });
          } else if (err) {
            return done(err);
          } else {
            logger.info("profile.id found. using existing google");
            // associate new google with user
            _user['google-oauth'] = _google.id;
            // preserve the login state by returning the existing user
            _user.save(done);
          }
        });
      }
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
  callback(null);
}
google.method('routes', routes, {
  description: 'sets routes for google in app'
});

google.dependencies = {
  'passport-google-oauth': '*'
};
google.license = 'MIT';
exports['auth-google-oauth'] = google;
