# passport-aliyun

[Passport](https://github.com/jaredhanson/passport) strategy for authenticating
with [Aliyun](http://www.aliyun.com/) using the OAuth 1.0a API.

This module lets you authenticate using Aliyun in your Node.js applications.
By plugging into Passport, Aliyun authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-aliyun

## Usage

#### Create an Application

Before using `passport-aliyun`, you must first get an Aliyun API key. If you
have not already done so, an API key can be requested at internal.
Your will be issued an API key and secret, which need to be provided to the
strategy.

#### Configure Strategy

The Aliyun authentication strategy authenticates users using an Aliyun
account and OAuth tokens.  The API key secret obtained from Aliyun are
supplied as options when creating the strategy.  The strategy also requires a
`verify` callback, which receives the access token and corresponding secret as
arguments, as well as `profile` which contains the authenticated user's Aliyun
profile.   The `verify` callback must call `cb` providing a user to complete
authentication.

    passport.use(new AliyunStrategy({
        consumerKey: ALIYUN_CONSUMER_KEY,
        consumerSecret: ALIYUN_CONSUMER_SECRET,
        callbackURL: "http://127.0.0.1:3000/auth/aliyun/callback"
      },
      function(token, tokenSecret, profile, cb) {
        User.findOrCreate({ aliyunId: profile.id }, function (err, user) {
          return cb(err, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'aliyun'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/aliyun',
      passport.authenticate('aliyun'));
    
    app.get('/auth/aliyun/callback', 
      passport.authenticate('aliyun', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

