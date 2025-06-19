import express from "express";
import controller from "./accounts.controller.js";
import methodNotAllowed from "../../errors/methodNotAllowed.js"
import rateLimit from 'express-rate-limit';

// Rate limiters, allows for max number of attempts per IP within a specified time frame. Max denotes number of tries.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 7, 
  message: {
    status: 429,
    message: "Too many login attempts. Please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: {
    status: 429,
    message: "Too many registration attempts. Try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const currentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50,
  message: {
    status: 429,
    message: "Too many re-authentication attempts. Please wait.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const logoutLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,
  message: {
    status: 429,
    message: "Too many logout attempts. Please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});


// const verifyLimiter = rateLimit({
//   windowMs: 60 * 60 * 1000, // 1 hour
//   max: 3,
//   message: {
//     status: 429,
//     message: "Too many verification attempts. Please check your email.",
//   },
//   standardHeaders: true,
//   legacyHeaders: false,
// });

const router = express.Router();

router.route("/register").post(loginLimiter, controller.add).all(methodNotAllowed);
router.route("/login").post(registerLimiter, controller.login).all(methodNotAllowed);
router.route("/current").post(currentLimiter, controller.current).all(methodNotAllowed);
router.route("/logout").post(logoutLimiter, controller.logout).all(methodNotAllowed);


export default router;