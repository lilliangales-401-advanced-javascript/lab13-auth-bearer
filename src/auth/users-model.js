'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Global variable
let used_tokens = {};

const users = new mongoose.Schema({
  username: {type:String, required:true, unique:true},
  password: {type:String, required:true},
  email: {type: String},
  role: {type: String, default:'user', enum: ['admin','editor','user']},
});

users.pre('save', function(next) {
  bcrypt.hash(this.password, 10)
    .then(hashedPassword => {
      this.password = hashedPassword;
      next();
    })
    .catch(console.error);
});

users.statics.createFromOauth = function(email) {

  if(! email) { return Promise.reject('Validation Error'); }

  return this.findOne( {email} )
    .then(user => {
      if( !user ) { throw new Error('User Not Found'); }
      console.log('Welcome Back', user.username);
      return user;
    })
    .catch( error => {
      console.log('Creating new user');
      let username = email;
      let password = 'none';
      return this.create({username, password, email});
    });

};

// decrypt/verify and then find the user based on the id
users.statics.authenticateToken = function(token){

  if (process.env.JWT_SINGLE_USE) {
    if (used_tokens.hasOwnProperty(token)) {
      throw new Error();
    } else {
      let parsedToken = jwt.verify(token, process.env.SECRET);
      let query = {_id: parsedToken.id};
      used_tokens[token] = 'token';
      return this.findOne(query);
    }
  } else {
    let parsedToken = jwt.verify(token, process.env.SECRET);
    let query = {_id: parsedToken.id};
    return this.findOne(query);

  }
};

users.statics.authenticateBasic = function(auth) {
  let query = {username:auth.username};
  return this.findOne(query)
    .then( user => user && user.comparePassword(auth.password) )
    .catch(error => {throw error;});
};

users.methods.comparePassword = function(password) {
  return bcrypt.compare( password, this.password )
    .then( valid => valid ? this : null);
};

users.methods.generateToken = function() {
  
  let token = {
    id: this._id,
    role: this.role,
  };

  if (process.env.JWT_EXPIRES) {
    let signOptions = {
      expiresIn: process.env.JWT_EXPIRES,
    };

    return jwt.sign(token, process.env.SECRET, signOptions);
  }
  return jwt.sign(token, process.env.SECRET);
};

module.exports = mongoose.model('users', users);
