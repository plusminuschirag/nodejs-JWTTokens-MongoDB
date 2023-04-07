require('dotenv').config();
require('./config/database').connect();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const express = require('express');
const User = require('./model/user');
const auth = require('./middleware/auth');
const app = express();

app.use(express.json());

// Logic goes here

app.post('/register', async (req, res) => {
  //1. Get User Input
  try {
    const { firstName, lastName, email, password } = req.body;
    //2. Validate User Input
    if (!(email && password && lastName && firstName)) {
      res.status(401).json({ message: 'All Inputs are required!!' });
    }
    //3. Validate if user already exists
    const oldUser = await User.findOne({ email });
    if (oldUser) {
      res.status(409).json({ message: 'User already exists!!' });
    }
    //4. Encrypt the user password
    encryptedPassword = await bcrypt.hash(password, 10);
    //5. Create a user in our database
    const user = await User.create({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password: encryptedPassword,
    });
    //6. Create a signed JWT Token
    //6.a Create token
    const token = jwt.sign({ userId: user._id, email }, process.env.TOKEN_KEY, {
      expiresIn: '2h',
    });

    //6.b save token
    user.token = token;

    //6.c return new user
    res.status(201).json(user);
  } catch (err) {
    console.log(err);
  }
});

app.post('/login', async (req, res) => {
  try {
    //1. Get User Input
    const { email, password } = req.body;

    //2. Validate User Input
    if (!(email && password)) {
      res
        .status(400)
        .json({ message: 'Email and Password Both are Required...' });
    }
    //3. Validate if user exists in db
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      //Create Token
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        { expiresIn: '2h' }
      );

      //Save User Token
      user.token = token;

      //user
      res.status(200).json(user);
    } else {
      res.status(400).json({ message: 'Invalid Credentials!!' });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post('/welcome', auth, (req, res) => {
  res.status(200).json({ message: 'Welcome 🙌🏻' });
});

module.exports = app;
