const asyncErrorBoundary = (delegate, defaultStatus = 500) => {
  return (request, response, next) => {
    Promise.resolve()
      .then(() => delegate(request, response, next))
      .catch((error = {}) => {
        const { status = defaultStatus, message = "Something went wrong!" } = error;
        next({
          status,
          message,
        });
      });
  };
}

module.exports = asyncErrorBoundary;

