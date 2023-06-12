// @ts-check
// @russfeld start
const express = require('express');
const router = express.Router();
const url = require('url');

const { logger } = require('@prairielearn/logger');
const { config } = require('../../lib/config');

router.get('/', function (req, res, next) {
  if (!config.hasCas || !config.casUrl || !config.casServiceUrl) {
    return next(new Error('CAS login is not enabled'));
  }

  // Set up the query parameter from configuration file.
  //
  // CAS authentication process adapted from:
  // https://github.com/BigDaddyXu/cas-authentication/blob/master/index.js#L244-L261
  //
  // Original code licensed under MIT License:
  // https://github.com/BigDaddyXu/cas-authentication/blob/master/LICENSE

  const query = {
    service: config.casServiceUrl,
    renew: false,
  };

  // FIXME: url.format deprecated
  const casurl =
    config.casUrl +
    url.format({
      pathname: '/login',
      query: query,
    });

  logger.verbose('Cas auth URL redirect: ' + casurl);

  // Redirect to the CAS login.
  res.redirect(casurl);
});

module.exports = router;
// @russfeld end
