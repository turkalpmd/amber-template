const { AuthenticationService, JWTStrategy } = require('@feathersjs/authentication');
const { oauth } = require('@feathersjs/authentication-oauth');
const totp2fa = require('./hooks/totp-2fa');
const authActivity = require('./hooks/auth-activity');
const authEmailOtp = require('./hooks/auth-email-otp');
const { iff } = require('feathers-hooks-common');

const { AnonymousStrategy, ActiveLocalStrategy, ApiKeyStrategy, ParticipantStrategy, WalkInParticipantStrategy } = require('./utils/auth-strategies');



module.exports = app => {
  const authentication = new AuthenticationService(app);

  authentication.register('jwt', new JWTStrategy());
  authentication.register('local', new ActiveLocalStrategy());
  authentication.register('anonymous', new AnonymousStrategy());
  authentication.register('apiKey', new ApiKeyStrategy());
  authentication.register('participant', new ParticipantStrategy());
  authentication.register('campaign', new WalkInParticipantStrategy());

  app.use('/authentication', authentication);
  const authenticationConfig = app.get('authentication');
  app.service('authentication').hooks({
    after: {
      create: [
        authActivity(),
        authEmailOtp(),
        iff(
          context => context.result.user.with2fa !== false && context.result.otp !== true,
          totp2fa({
            usersService: 'user',
            applicationName: authenticationConfig.jwtOptions.issuer,
            cryptoUtil: app.get('crypto')
          })
        )
      ]
    }
  });
  app.configure(oauth());
};
