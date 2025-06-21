import bcrypt from "bcrypt";
import jwt, { verify } from "jsonwebtoken";
import validator from "validator";
import service from "./accounts.service.js";
import asyncErrorBoundary from "../../errors/asyncErrorBoundary.js"
import syncErrorBoundary from "../../errors/syncErrorBoundary.js";
import hasProperties from "../../utils/hasProperties.js";
import hasValidProperties from "../../utils/hasValidProperties.js";
import crypto from "crypto";
import { resolve } from "path";
import handleErrors from "../../errors/errorLogging.js";
import isMobileApp from "../../utils/isMobileApp.js";

//Helper functions - - - - - - - - - - - - - - - - - - - -
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


//Add functionality later
const sendEmail = (
  to,
  subject,
  text,
  from = "Advice Room <admin@adviceroom.findOut"
) => {
  const apiKey = process.env.MAILGUN_API_KEY;
  const domain = "adviceroom.net";
  const mg = mailgun({ apiKey, domain });
  const data = { from, to, subject, text };
  return new Promise((resolve, reject) => {
    mg.messages().send(data, (error, body) => {
      if (error) {
        return reject(error);
      } else {
        return resolve(body);
      }
    });
  });
};

const isStrongPassword = (password) => {
  const hasNoSpaces = !/\s/.test(password);
  const isValidStrongPassword = validator.isStrongPassword(password, {
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1,
  });
  return isValidStrongPassword && hasNoSpaces;
};

//Validation Middleware - - - - - - - - - - - - - - - - - - - -

//For the property verification functions, examine try/catch vs syncError Boundary
const validRegisterProps = ["first_name", "last_name", "email", "password"];
const areRegistrationFieldsValid = hasValidProperties(validRegisterProps);

const requiredRegisterFields = ["first_name", "last_name", "email", "password"];
const hasAllRegisterFields = hasRequiredProperties(requiredRegisterFields);

const validLoginProps = ["email", "password", "remember"];
const areLoginFieldsValid = hasValidProperties(validLoginProps);

const requiredLoginFields = ["email", "password"];
const hasAllLoginFields = hasRequiredProperties(requiredLoginFields);

const isValidName = (req, res, next) => {
  const { first_name, last_name } = req.body;
  const minLength = 2;
  const maxLength = 30;
  const nameRegex = /^[A-Za-z\s]+$/;

  const isValidFirst =
    first_name.length >= minLength &&
    first_name.length <= maxLength &&
    nameRegex.test(first_name);
  const isValidLast =
    last_name.length >= minLength &&
    last_name.length <= maxLength &&
    nameRegex.test(last_name);

  if (isValidFirst && isValidLast) {
    return next();
  } else {
    return next({
      status: 400,
      message:
        "First name and last name must be between 2 and 30 characters in length and contain only letters and spaces.",
    });
  }
};

//errors in this function and similar would go to error handler - check that code so error messages don't get send to api users
const isValidEmail = (req, res, next) => {
  const { email } = req.body;
  const emailPattern = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;
  if (emailPattern.test(email) && validator.isEmail(email)) {
    return next();
  } else {
    return next({
      status: 400,
      message: `Please enter a valid email address.`,
    });
  }
};

const isAlreadyUser = async (req, res, next) => {
  const { email } = req.body;
  const user = await service.findByEmail(email);
  if (user) {
    return next({ status: 409, message: `User: ${email} already exists.` });
  } else {
    res.locals.user = req.body;
    return next();
  }
};

const formatUser = (req, res, next) => {
  req.user = req.body;
  return next();
};

const doesUserExist = async (req, res, next) => {
  const { email } = req.user;
  const user = await service.findByEmail(email);
  if (user) {
    res.locals.user = {
      id: user.id,
      name: user.first_name,
      email: user.email,
      password: user.password,
    };
    return next();
  } else {
    return next({
      status: 409,
      message: `User: ${email} does not exist. Please register for access.`,
    });
  }

};

const doesPasswordMatch = (req, res, next) => {
  const { password } = req.body;
  const { password: hash } = res.locals.user;
  const match = compareHashedData(password, hash);
  if (match) {
    return next();
  } else {
    return next({ status: 400, message: `Incorrect password.` });
  }
};

const addUser = async (req, res, next) => {
  const { first_name, last_name, email, password } = res.locals.user;
  const hashedPassword = await hashData(password);
  const verification_number = await hashData(generateRandomCode());
  const user = {
    first_name,
    last_name,
    email,
    password: hashedPassword,
    verification_number,
  };
  const newUser = await service.insertUser(user);
  res.locals.user = newUser;
  next();

};

const authorize = (req, res, next) => {
  if (res.locals.userAgent === "web") {
    const { refreshToken, accessToken } = req.cookies;

    if (!refreshToken) {
      return next({ status: 401, message: "Resource requires refresh token" });
    }

    jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_TOKEN_SECRET,
      (err, decoded) => {
        if (err) {
          handleErrors(err);
          return next({ status: 401, message: "Refresh token is invalid" });
        }

        if (decoded.ver != process.env.CURRENT_REFRESH_TOKEN_VERSION)
          return next({ status: 401, message: "Refresh token is invalid" });
        req.user = decoded;
        return next();
      }
    );
  } else if (res.locals.userAgent === "mobile") {
    const bearerTokenString = req.headers.authorization;

    if (!bearerTokenString)
      return next({
        status: 401,
        message: "Resource requires Bearer token in Authorization header",
      });
    if (bearerTokenString.split(" ").length !== 2)
      return next({ status: 400, message: "Bearer token is malformed" });

    const [bearer, requestToken] = bearerTokenString.split(" ");

    if (bearer !== "Bearer" || !requestToken)
      return next({ status: 400, message: "Bearer token is malformed" });

    jwt.verify(
      requestToken,
      process.env.JWT_REFRESH_TOKEN_SECRET,
      (err, decoded) => {
        if (err) {
          handleErrors(err);
          return next({ status: 401, message: "Refresh token is invalid" });
        }

        if (decoded.ver != process.env.CURRENT_REFRESH_TOKEN_VERSION)
          return next({ status: 401, message: "Refresh token is invalid" });
        req.user = decoded;
        return next();
      }
    );
  }
};

const refreshTokens = async (refreshToken, remember) => {
  try {
    const refreshDecoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_TOKEN_SECRET
    );
    const user = await service.findByEmail(refreshDecoded.email);
    if (!user) {
      throw new Error("User not found");
    }

    const isMatch = refreshToken === user.refresh_token;

    if (!isMatch) {
      throw new "Error validating user, please login again."();
    }

    const newRefreshToken = await jwt.sign(
      {
        id: user.id,
        email: user.email,
        ver: process.env.CURRENT_REFRESH_TOKEN_VERSION,
      },
      process.env.JWT_REFRESH_TOKEN_SECRET,
      { expiresIn: remember ? "7d" : "24h" }
    );

    const newAccessToken = await jwt.sign(
      {
        id: user.id,
        email: user.email,
        ver: process.env.CURRENT_ACCESS_TOKEN_VERSION,
      },
      process.env.JWT_ACCESS_TOKEN_SECRET,
      { expiresIn: "1h" }
    );
    return { newAccessToken, newRefreshToken };
  } catch (error) {
    throw "Invalid or expired refresh token";
  }
};

const sendNewToken = async (req, res, next) => {
  const remember = req.body?.remember;
  const { user } = res.locals;

  let refreshToken;
  if (res.locals.userAgent === "web") {
    refreshToken = req.cookies.refreshToken;
  } else if (res.locals.userAgent === "mobile") {
    const bearerTokenString = req.headers.authorization;

    if (!bearerTokenString)
      return next({
        status: 401,
        message: "Resource requires Bearer token in Authorization header",
      });
    if (bearerTokenString.split(" ").length !== 2)
      return next({ status: 400, message: "Bearer token is malformed" });

    const [bearer, token] = bearerTokenString.split(" ");
    if (bearer !== "Bearer" || !token)
      return next({ status: 400, message: "Bearer token is malformed" });

    refreshToken = token;
  }

  let newTokens;
  newTokens = await refreshTokens(refreshToken, remember);
  const { id } = req.user;
  const updatedRecord = await service.updateRefreshToken(
    id,
    newTokens.newRefreshToken
  );
  if (!updatedRecord)
    throw "Unable to send new tokens, please try logging in again.";
}

const { newAccessToken, newRefreshToken } = newTokens;

if (res.locals.userAgent === "web") {
  try {
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      // secure: true,
      origin: process.env.ADMIN_CORS_ORIGIN || "http://localhost:5173",
      // sameSite: "strict",
      maxAge: remember ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000, // 24 hours
    });
    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      // secure: true,
      origin: process.env.ADMIN_CORS_ORIGIN || "http://localhost:5173",
      // sameSite: "strict",
      maxAge: 60 * 60 * 1000, // 1hr
    });
    res
      .status(200)
      .json({ user: { id: user.id, name: user.name }, isLoggedIn: true });
  } catch (error) {
    next({
      status: 500,
      message:
        "Something went wrong. Internal server error while attempting to login.",
    });
  }
} else if (res.locals.userAgent === "mobile") {
  try {
    res
      .status(200)
      .json({
        refreshToken: newRefreshToken,
        accessToken: newAccessToken,
        user: { id: user.id, name: user.name },
        isLoggedIn: true,
      });
  } catch (error) {
    handleErrors(error);
    next({
      status: 500,
      message:
        "Something went wrong. Internal server error creating login token.",
    });
  }
}


const sendVerificationEmail = async (req, res, next) => {
  const { user } = res.locals;
  const { refreshToken, accessToken } = await generateToken(user);
  const text = `To verify account please navigate to: https://localhost/accounts/verify?user=${token}?code=${user.verification_number}`;
  return next();
  //Right now email service is not working, need to ask michael about api key = won't work domains other than cpi it seems.
};

//Verification email link should send user to client app, client app makes a request to backend

const verifyEmail = async (req, res, next) => {
  const { verification_number } = req.body;
  const validToken = "";
  try {
    const updatedUser = service.updateUserByEmail(
      { verification_number: null, is_verified: true },
      validToken.email
    );
    res.locals.user = updatedUser;
    return next();
  } catch (error) {
    handleErrors(error);
    return next({
      status: 500,
      message: `Internal server error. Verification failed`,
    });
  }
};

//Route Handlers
const add = (req, res) => {
  const user = res.locals.user;
  res
    .status(200)
    .json({
      message: "User successfully added",
      id: user.id,
      user: user.email,
    });
};

const login = async (req, res, next) => {
  const { user } = res.locals;
  if (res.locals.userAgent === "web") {
    try {
      const { refreshToken, accessToken } = await generateToken(
        user,
        user.remember
      );
      await service.updateRefreshToken(user.id, refreshToken);
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        // secure: true,
        origin: process.env.ADMIN_CORS_ORIGIN || "http://localhost:5173",
        // sameSite: "strict",
        maxAge: user.remember ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000, // 24 hrs,
      });
      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        // secure: true,
        origin: process.env.ADMIN_CORS_ORIGIN || "http://localhost:5173",
        // sameSite: "strict",
        maxAge: 60 * 60 * 1000, // 1hr
      });
      res.status(200).json({ message: "Logged in successfully" });
    } catch (error) {
      handleErrors(error);
      next({
        status: 500,
        message:
          "Something went wrong. Internal server error while attempting to login.",
      });
    }
  } else if (res.locals.userAgent === "mobile") {
    try {
      const { refreshToken, accessToken } = await generateToken(user);
      res.status(200).json({ refreshToken, accessToken });
    } catch (error) {
      next({
        status: 500,
        message:
          "Something went wrong. Internal server error creating login token.",
      });
    }
  }
};

const current = (req, res) => {
  const { user } = res.locals;
  res
    .status(200)
    .json({ user: { id: user.id, name: user.name }, isLoggedIn: true });
};

const verified = (req, res) => {
  const { id, email, is_verified } = res.locals.user;
  res.status(200).json({ id, email, is_verified });
};

const logout = (req, res) => {
  const env = process.env.ENV;
  const additionalProps = env === 'dev' ? {} : env === "prod" ? {
    secure: true,
    sameSite: "strict"
  } : {}
  res.clearCookie("accessToken", {
    httpOnly: true,
    origin: process.env.ADMIN_CORS_ORIGIN || "http://localhost:5173",
    ...additionalProps
  });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    origin: process.env.ADMIN_CORS_ORIGIN || "http://localhost:5173",
    ...additionalProps
  });
  res.status(200).json({ isLoggedIn: false });
};

//Exports

//Exported as add
const addMiddleware = [
  isMobileApp,
  areRegistrationFieldsValid,
  hasAllRegisterFields,
  isValidName,
  isValidEmail,
  syncErrorBoundary(isStrongPassword, "registration - password verification"),
  asyncErrorBoundary(isAlreadyUser, "registraton - user verification"),
  asyncErrorBoundary(addUser),
  // sendVerificationEmail,
  add,
];

//Exported as login
const loginMiddleware = [
  isMobileApp,
  areLoginFieldsValid,
  hasAllLoginFields,
  isValidEmail,
  isStrongPassword,
  formatUser,
  asyncErrorBoundary(doesUserExist, 'login - user verification'),
  syncErrorBoundary(doesPasswordMatch, 'login - password validation'),
  login,
];

//Exported as current
const currentMiddleware = [
  isMobileApp,
  authorize,
  asyncErrorBoundary(doesUserExist, 'current - user verification'),
  asyncErrorBoundary(sendNewToken, 'current - token creation')
];

//Exported as verify
const verifyMiddleware = [
  isMobileApp,
  syncErrorBoundary(authorize, 'verify - user authorization'),
  verifyEmail,
  verified
];

//Exported as renew
// const renewMiddleware = [isMobileApp, 
//   authorize, 
//   doesUserExist, 
//   sendNewToken
// ];

export { logout };

export default {
  add: addMiddleware,
  login: loginMiddleware,
  current: currentMiddleware,
  // renew: renewMiddleware,
  verify: verifyMiddleware,
};

