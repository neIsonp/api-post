const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const User = require('../models/user');

exports.signup = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    const error = new Error('Validation failed');
    error.statusCode = 422;
    error.data = errors.array();
    throw error;
  }

  const { email, name, password } = req.body;

  bcrypt.hash(password, 12).then(hashedPw => {
    const user = new User({ email: email, password: hashedPw, name: name });
    return user.save();
  }).then(result => {
    res.status(201).json({ message: 'User created!', userId: result._id });
  }).catch(err => {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  });
}

exports.login = (req, res, next) => {
  const { email, password } = req.body;
  let loadedUser;

  User.findOne({ email: email }).then(user => {
    if (!user) {
      const err = new Error("A user with this email could not be found.");
      err.statusCode = 401;
      throw err;
    }

    loadedUser = user;

    return bcrypt.compare(password, user.password);

  }).then(isEqual => {
    if (!isEqual) {
      const err = new Error("Wrong password.");
      err.statusCode = 401;
      throw err;
    }

    const token = jwt.sign(
      { email: loadedUser.email, userId: loadedUser._id },
      'somesupersecrect',
      { expiresIn: '1h' }
    );

    res.status(200).json({ token: token, userId: loadedUser._id.toString() });
  }).catch((err) => {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  });
}; 