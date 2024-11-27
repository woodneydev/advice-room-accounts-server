const becrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const asyncErrorBoundary = require("../../errors/asyncErrorBoundary");
const hasProperties = require("../../errors/hasProperties");
const crypto = require("crypto");
const { resolve } = require("path");

/** TRY/CATCH not utilized in favor of async error boundary **/

/** Helper Functions **/
const hashData = async (password, saltRounds = 12) => {
  const salt = await becrypt.genSalt(saltRounds);
  const hash = await becrypt.hash(password, salt);
  return hash;
};

const compareHashedData = async (password, hash) => {
  const matchFound = await becrypt.compare(password, hash);
  return matchFound;
};

const generateRandomCode = (codeLength = 6) => {
  const characters =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  let code = "";

  for (let i = 0; i < codeLength; i++) {
    const randomIndex = crypto.randomInt(0, characters.length);
    code += characters[randomIndex];
  }

  return code;
};

const generateToken = async (user) => {
  const accessToken = await jwt.sign(
    {
      id: user.id,
      email: user.email,
      ver: process.env.CURRENT_ACCESS_TOKEN_VERSION,
    },
    process.env.JWT_ACCESS_TOKEN_SECRET,
    { expiresIn: "15m" }
  );

  const refreshToken = await jwt.sign(
    {
      id: user.id,
      email: user.email,
      ver: process.env.CURRENT_REFRESH_TOKEN_VERSION,
    },
    process.env.JWT_REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" }
  );

  return { accessToken, refreshToken };
};

const verifyToken = (token, type = "access") => {
  let key;
  if (type === "access") key = process.env.JWT_ACCESS_TOKEN_SECRET;
  if (type === "refresh") key = process.env.JWT_REFRESH_TOKEN_SECRET;

  return new Promise((resolve, reject) => {
    jwt.verify(token, key, (err, decoded) => {
      if (err) {
        reject(err);
      } else {
        resolve(decoded);
      }
    });
  });
};

const sendEmail = (to, subject, text, from = "Advice Room <admin@adviceroom.net") => {
    const apiKey = process.env.MAILGUN_API_KEY;
    const domain = "adviceroom.net";
    const mg = mailgun( {apiKey, domain});
    const data = {from, to, subject, text};
    return new Promise((resolve, reject) => {
        mg.messages().send(data, (error, body) => {
            if (error) {
                return reject(error)
            } else {
                return resolve(body);
            }
        })
    })
}
