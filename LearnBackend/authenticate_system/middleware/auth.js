const jwt = require("jsonwebtoken");

// model is optional

const auth = (req, res, next) => {
  console.log(req.cookies);
  const token =
    req.header("Authorization")?.replace("Bearer ", "") ||
    req.cookies.token ||
    req.body.token;

  if (!token) {
    res.status(403).send("token is missing!!!");
  }

  try {
    const decode = jwt.verify(token, process.env.SECRET_KEY);
    console.log(decode);
    req.user = decode;
    //bring in info from db
  } catch (error) {
    res.status(401).send("invalid token!!!");
  }

  return next();
};

module.exports = auth;
