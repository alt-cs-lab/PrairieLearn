// @ts-check
// authCallbackCas/authCallbackCas.js
// @russfeld start
// const assert = require('assert');
import { Router } from 'express';
import asyncHandler from 'express-async-handler';
import { logger } from '@prairielearn/logger';
import url from 'url';
import http from 'http';
import https from 'https';
import { parseString as parseXML } from 'xml2js';
import { normalize, stripPrefix } from 'xml2js/lib/processors.js'

import * as authnLib from '../../lib/authn.js';
import { config } from '../../lib/config.js';

const router = Router();

const validate = function (body, callback) {
  parseXML(
    body,
    {
      trim: true,
      normalize: true,
      explicitArray: false,
      tagNameProcessors: [normalize, stripPrefix],
    },
    function (err, result) {
      if (err) {
        return callback(new Error('Response from CAS server was bad.'));
      }
      try {
        var failure = result.serviceresponse.authenticationfailure;
        if (failure) {
          return callback(new Error('CAS authentication failed (' + failure.$.code + ').'));
        }
        var success = result.serviceresponse.authenticationsuccess;
        if (success) {
          return callback(null, success.user, success.attributes);
        } else {
          return callback(new Error('CAS authentication failed.'));
        }
      } catch (err) {
        console.log(err);
        return callback(new Error('CAS authentication failed.'));
      }
    }
  );
};

router.get(
  '/',
  asyncHandler(async (req, res, _next) => {
    if (!config.hasCas || !config.casUrl || !config.casServiceUrl) {
      throw new Error('CAS login is not enabled');
    }

    // CAS ticket verification code below adapted from:
    // https://github.com/BigDaddyXu/cas-authentication/blob/master/index.js#L291
    //
    // Original code licensed under MIT License:
    // https://github.com/BigDaddyXu/cas-authentication/blob/master/LICENSE
    const ticket = req.query.ticket;
    if (ticket == null) {
      throw new Error('No "ticket" query parameter for authCallbackCas');
    } else if (typeof ticket !== 'string') {
      throw new Error(`Invalid 'ticket' query parameter for authCallbackCas: ${ticket}`);
    }

    logger.verbose('Got CAS auth with ticket: ' + ticket);

    const parsed_cas_url = url.parse(config.casUrl);
    const cas_host = parsed_cas_url.hostname;
    const cas_port = parsed_cas_url.port
      ? parsed_cas_url.port
      : parsed_cas_url.protocol === 'http:'
      ? 80
      : 443;
    const cas_path = parsed_cas_url.pathname;
    const request_client = parsed_cas_url.protocol === 'http:' ? http : https;

    var requestOptions = {
      host: cas_host,
      port: cas_port,
      method: 'GET',
    };

    // FIXME: url.format deprecated
    requestOptions.path = url.format({
      pathname: cas_path + '/p3/serviceValidate',
      query: {
        service: config.casServiceUrl,
        ticket: ticket,
      },
    });

    var request = request_client.request(
      requestOptions,
      function (response) {
        response.setEncoding('utf8');
        var body = '';
        response.on(
          'data',
          function (chunk) {
            return (body += chunk);
          }.bind(this)
        );
        response.on(
          'end',
          function () {
            validate(
              body,
              async function (err, user, attributes) {
                if (err) {
                  logger.error('CAS ticket validation error!', err);
                  res.sendStatus(401);
                } else {
                  logger.verbose('CAS authentication success for user ' + user);
                  logger.verbose('CAS attributes', attributes);
                  // assert(user);
                  let authnParams = {
                    uid: user,
                    name: user,
                    uin: user,
                    provider: 'CAS',
                  };
                  await authnLib.loadUser(req, res, authnParams, {
                    redirect: true,
                  });
                }
              }.bind(this)
            );
          }.bind(this)
        );
        response.on(
          'error',
          function (err) {
            logger.error('Response error from CAS: ', err);
            res.sendStatus(401);
          }.bind(this)
        );
      }.bind(this)
    );

    request.on(
      'error',
      function (err) {
        logger.error('Request error with CAS: ', err);
        res.sendStatus(401);
      }.bind(this)
    );

    request.end();
  })
);

export default router;
// @russfeld end
