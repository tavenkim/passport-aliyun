// Load modules.
var util = require('util')
  , urllib = require('urllib')
  , OAuthStrategy = require('passport-oauth1');


/**
 * `Strategy` constructor.
 *
 * The Aliyun authentication strategy authenticates requests by delegating to
 * Aliyun using the OAuth protocol.
 *
 * Applications must supply a `verify` callback which accepts a `token`,
 * `tokenSecret` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `consumerKey`     identifies client to Aliyun
 *   - `consumerSecret`  secret used to establish ownership of the consumer key
 *   - `callbackURL`     URL to which Aliyun will redirect the user after obtaining authorization
 *
 * Examples:
 *
 *     passport.use(new AliyunStrategy({
 *         consumerKey: '123-456-789',
 *         consumerSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/aliyun/callback'
 *       },
 *       function(token, tokenSecret, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.requestTokenURL = options.requestTokenURL || 'https://account.aliyun.com/oauth/request_token';
  options.accessTokenURL = options.accessTokenURL || 'https://account.aliyun.com/oauth/access_token';
  options.userAuthorizationURL = options.userAuthorizationURL || 'https://account.aliyun.com/oauth/authorize';
  options.sessionKey = options.sessionKey || 'oauth:aliyun';

  OAuthStrategy.call(this, options, verify);
  this.name = 'aliyun';
  this._oauth._userProfileURL = options.userProfileURL || 'https://account.aliyun.com/openapi/id/load'
}

// Inherit from `OAuthStrategy`.
util.inherits(Strategy, OAuthStrategy);


/**
 * Retrieve user profile from Aliyun.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `id`
 *   - `shard`
 *
 * Note that because Aliyun supplies basic profile information in query
 * parameters when redirecting back to the application, loading of Aliyun
 * profiles *does not* result in an additional HTTP request.
 *
 * @param {String} token
 * @param {String} tokenSecret
 * @param {Object} params
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (token, tokenSecret, params, done) {
  urllib.request(this._oauth._userProfileURL, {
    headers: {
      'Authorization': this._oauth.authHeader(this._oauth._userProfileURL, token, tokenSecret)
    },
    dataType: 'json'
  }, function (err, data) {
    return done(err, data);
  })
}

// Expose constructor.
module.exports = Strategy;
