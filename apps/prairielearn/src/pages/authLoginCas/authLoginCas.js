// @ts-check
// @russfeld start
import { Router } from 'express';
import url from 'url';

import { logger } from '@prairielearn/logger';
import { config } from '../../lib/config.js';

const router = Router();

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

export default router;
// @russfeld end
