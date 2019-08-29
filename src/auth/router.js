'use strict';

const express = require('express');
const authRouter = express.Router();

const User = require('./users-model.js');
const auth = require('./middleware.js');
const oauth = require('./oauth/google.js');

/** This is a route to get one book
* @route POST /signup
* @param {object} req
* @param {object} res
* @param {function} next
* @returns {object} send req.token
*/
authRouter.post('/signup', (req, res, next) => {
  let user = new User(req.body);
  user.save()
    .then( (user) => {
      req.token = user.generateToken();
      req.user = user;
      res.set('token', req.token);
      res.cookie('auth', req.token);
      res.send(req.token);
    }).catch(next);
});

/** This is a route to get one book
 * @route POST /signin
 * @param {object} req
 * @param {object} res
 * @param {function} next
 * @returns {object} send req.token
 */
authRouter.post('/signin', auth, (req, res, next) => {
  res.cookie('auth', req.token);
  res.send(req.token);
});

/** This is a route to get one book
 * @route POST /oath
 * @param {object} req
 * @param {object} res
 * @param {function} next
 * @returns {object} send req.token
 */
authRouter.get('/oauth', (req,res,next) => {
  oauth.authorize(req)
    .then( token => {
      res.status(200).send(token);
    })
    .catch(next);
});

authRouter.post('/key', auth, (req,res,next) => {
  let key = req.user.generateToken('key');
  res.send(key);
});

module.exports = authRouter;
