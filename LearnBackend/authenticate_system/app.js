require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const User = require("./model/User");
const auth = require("./middleware/auth");

const app = express();
app.use(express.json()); // since express cannot handle the json file directly. it has to use middleware for it.
app.use(cookieParser()); // we can't directly access the cookie, for that we have to use the package cookie-parser

app.get("/", (req, res) => {
  res.send("<h1>Hello vansh welcome to the backend course</h1>");
});

app.post("/register", async (req, res) => {
  try {
    const { firstname, lastname, email, password } = req.body;

    if (!(firstname && lastname && email && password)) {
      res.status(400).send("All fields are required!");
    }

    const existingUser = await User.findOne({ email }); // will return PROMISE

    if (existingUser) {
      res.status(400).send("User already exists!");
    }

    const myEncPassword = await bcrypt.hash(password, 10); // 10 is salt - how many rounds of hash u want

    // anything happens with mongoose returns a promise
    // use .then and .catch
    const user = await User.create({
      firstname,
      lastname,
      email: email.toLowerCase(),
      password: myEncPassword,
    });

    // token generation - we r using jwt
    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.SECRET_KEY,
      {
        expiresIn: "1h",
      }
    );
    user.token = token;

    // handle password situation
    user.password = undefined;
    res.status(201).json(user);
  } catch (error) {
    console.log(error);
  }
});

//assume database is in other continent
//so we have to use async-await
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!(email && password)) {
      res.status(400).send("All fields are required!!!");
    }

    const user = await User.findOne({ email });
    if (!user) {
      res.status(400).send("You are not registered. Please register first!!!");
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (!isPasswordCorrect) {
      res.status(400).send("Password entered is wrong!!!");
    }

    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.SECRET_KEY,
      { expiresIn: "1h" }
    );

    user.token = token;
    user.password = undefined;
    //res.status(200).json(user);

    //if u want to use cookies
    const options = {
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      httpOnly: true, // will be accessible by backend only
    };

    res.status(200).cookie("token", token, options).json({
      success: true,
    });
  } catch (error) {
    console.log(error);
  }
});

app.get("/dashboard", auth, (req, res) => {
  res.status(200).send("U r able to access the secret information");
});

module.exports = app;
