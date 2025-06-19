const isMobileApp = (req, res, next) => {
    //For now all requests will be webapps
    const isMobileApp = false // checks for mobile
    if (isMobileApp) {
      res.locals.userAgent = "mobile"
      return next();
    } else if (!isMobileApp) {
      res.locals.userAgent = "web"
      return next();
    }
};

export default isMobileApp