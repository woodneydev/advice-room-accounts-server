import bcrypt from "bcrypt";
import jwt, { verify } from "jsonwebtoken";
import validator from "validator";
import service from "./accounts.service.js";
import asyncErrorBoundary from "../../errors/asyncErrorBoundary.js"
import hasProperties from "../../utils/hasProperties.js";
import hasValidProperties from "../../utils/hasValidProperties.js";
import crypto from "crypto";
import { resolve } from "path"

//Helper functions
const hashData = async (password, saltRounds = 12) => {
  try {
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    return hash;
  } catch (error) {
    throw new Error(`${error}`);
  }
};

const compareHashedData = async (password, hash) => {
  try {
    const matchFound = await bcrypt.compare(password, hash);
    return matchFound;
  } catch (error) {
    throw new Error(`${error}`);
  }
};

const generateRandomCode = () => {
  const characters =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  let code = "";

  for (let i = 0; i < 6; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    code += characters.charAt(randomIndex);
  }

  return code;
};

const generateToken = async (user, remember) => {
  try {
    const accessToken = await jwt.sign(
      {
        id: user.id,
        email: user.email,
        ver: process.env.CURRENT_ACCESS_TOKEN_VERSION,
      },
      process.env.JWT_ACCESS_TOKEN_SECRET,
      { expiresIn: "1h" }
    );
    const refreshToken = await jwt.sign(
      {
        id: user.id,
        email: user.email,
        ver: process.env.CURRENT_REFRESH_TOKEN_VERSION,
      },
      process.env.JWT_REFRESH_TOKEN_SECRET,
      { expiresIn: remember ? "7d" : "24h" }
    );

    return { accessToken, refreshToken };
  } catch (error) {
    throw error;
  }
};

const verifyToken = (token) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.JWT_KEY, (err, decoded) => {
      if (err) {
        reject(err);
      } else {
        resolve(decoded);
      }
    });
  });
};

const handleErrors = require("../../utils/errorLogging");

//Add functionality later
const sendEmail = () => {

};

//Validation Middleware
const isMobileApp = require("../../utils/isMobileApp");
const validRegisterProps = ["first_name", "last_name", "email", "password"];
const areRegistrationFieldsValid = hasValidProperties(validRegisterProps);

const requiredRegisterFields = ["first_name", "last_name", "email", "password"];
const hasAllRegisterFields = hasRequiredProperties(requiredRegisterFields);

const validLoginProps = ["email", "password", "remember"];
const areLoginFieldsValid = hasValidProperties(validLoginProps);

const requiredLoginFields = ["email", "password"];
const hasAllLoginFields = hasRequiredProperties(requiredLoginFields);

const isStrongPassword = (req, res, next) => {
  const { password } = req.body;
  const minLength = 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*()_+{}\[\]:;<>,.?~\\-]/.test(password);

  if (
    password.length >= minLength &&
    hasUppercase &&
    hasLowercase &&
    hasDigit &&
    hasSpecialChar
  ) {
    return next();
  } else {
    return next({
      status: 400,
      message:
        "Password must have at least 8 characters, including an uppercase letter, a lowercase letter, a digit, and a special character.",
    });
  }
};

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
  try {
    const user = await service.findByEmail(email);
    if (user) {
      return next({ status: 409, message: `User: ${email} already exists.` });
    } else {
      res.locals.user = req.body;
      return next();
    }
  } catch (error) {
    handleErrors(error);
    return next({
      status: 500,
      message: `Internal server error. Unable to verify whether ${email} is already a user. Please try again later.`,
    });
  }
};

const formatUser = (req, res, next) => {
  req.user = req.body;
  return next();
};

const doesUserExist = async (req, res, next) => {
  const { email } = req.user;
  try {
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
  } catch (error) {
    handleErrors(error);
    return next({
      status: 500,
      message: `Internal server error. Could not find email entry for ${email}. Please try logging in later.`,
    });
  }
};

const doesPasswordMatch = (req, res, next) => {
  const { password } = req.body;
  const { password: hash } = res.locals.user;

  try {
    const match = compareHashedData(password, hash);
    if (match) {
      return next();
    } else {
      return next({ status: 400, message: `Incorrect password.` });
    }
  } catch (error) {
    handleErrors(error);
    return next({
      status: 500,
      message: `Internal server error. Could not validate password. Please try logging in later.`,
    });
  }
};

const addUser = async (req, res, next) => {
  const { first_name, last_name, email, password } = res.locals.user;
  console.log("firstName ", first_name);
  try {
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
    console.log("newuser => ", newUser);
    res.locals.user = newUser;
    next();
  } catch (error) {
    handleErrors(error);
    return next({
      status: 500,
      message: `Internal server error registering ${email}. Please try again later`,
    });
  }
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
  try {
    newTokens = await refreshTokens(refreshToken, remember);
    const { id } = req.user;
    const updatedRecord = await service.updateRefreshToken(
      id,
      newTokens.newRefreshToken
    );
    if (!updatedRecord)
      throw "Unable to send new tokens, please try logging in again.";
  } catch (error) {
    handleErrors(error);
    return next({
      status: 500,
      message:
        "Internal server error. Was unable to generate new refresh token. Please login again.",
    });
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
};

const sendVerificationEmail = async (req, res, next) => {
  const { user } = res.locals;
  const { refreshToken, accessToken } = await generateToken(user);
  const text = `To verify account please navigate to: https://localhost/accounts/verify?user=${token}?code=${user.verification_number}`;
  console.log("verify_link ==> ", text);
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
  console.log("user ->", user);
  res
    .status(200)
    .json({
      message: "User successfully added",
      id: user.id,
      user: user.email,
    });
};

const login = async (req, res, next) => {
  console.log("made it here login");

  const { user } = res.locals;
  console.log(user);
  if (res.locals.userAgent === "web") {
    try {
      const { refreshToken, accessToken } = await generateToken(
        user,
        user.remember
      );
      console.log(user.id);
      await service.updateRefreshToken(user.id, refreshToken);
      console.log("did it get here");
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
  res.clearCookie("accessToken", {
    httpOnly: true,
    origin: process.env.ADMIN_CORS_ORIGIN || "http://localhost:5173",
    // secure: true,
    // sameSite: "strict",
  });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    origin: process.env.ADMIN_CORS_ORIGIN || "http://localhost:5173",
    // secure: true,
    // sameSite: "strict",
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
  isStrongPassword,
  isAlreadyUser,
  addUser,
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
  doesUserExist,
  doesPasswordMatch,
  login,
];

//Exported as current
const currentMiddleware = [
  isMobileApp, 
  authorize, 
  doesUserExist, 
  sendNewToken
];

//Exported as verify
const verifyMiddleware = [
  isMobileApp, 
  authorize, 
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

