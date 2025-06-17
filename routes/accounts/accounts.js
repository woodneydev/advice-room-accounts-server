const router = require("express").Router();

router.route("/register").post(controller.add).all(methodNotAllowed);
router.route("/login").post(controller.login).all(methodNotAllowed);
router.route("/current").post(controller.current).all(methodNotAllowed);
router.route("/logout").post(controller.logout).all(methodNotAllowed);

module.exports = router;