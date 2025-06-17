function hasValidProperties(...validProperties) {
    return function (req, res, next) {
      const data  = req.body;
  
      try {
        Object.keys(data).forEach((property) => {
          if (!validProperties.includes(property)) {
            const error = new Error(`'${property}' property is not valid.`);
            error.status = 400;
            throw error;
          }
        });
        next();
      } catch (error) {
        next(error);
      }
    };
  }
  
  module.exports = hasValidProperties;