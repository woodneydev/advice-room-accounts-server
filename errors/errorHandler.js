
const errorHandler = (error, request, response, next) => {
  let { status = 500, message = "Something went wrong!" } = error;
  if (typeof message !== "string") {
    message = "An unexpected error occurred";
  }

  console.error(error); // log for now, in the future switch to winston and log to db
  response.status(status).json({ error: message });
};

export default errorHandler;
