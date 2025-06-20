
const errorHandler = (error, request, response, next) => {
  let { status = 500, message = "Something went wrong!" } = error;
  if (typeof message !== "string") {
    message = "An unexpected error occurred";
  }

  console.error(error); // log for now, in the future switch to winston and log to db
  response.status(status).json({ error: message });
};

export default errorHandler;

// const errorHandler = (error, request, response, next) => {
//   // Log the full error for debugging (but don't send to user)
//   console.error("Full error details:", {
//     name: error.name,
//     message: error.message,
//     stack: error.stack,
//     status: error.status,
//     timestamp: new Date().toISOString(),
//     url: request.originalUrl,
//     method: request.method,
//     userAgent: request.get('User-Agent'),
//     ip: request.ip
//   });
  
//   // Determine status code
//   const status = error.status || 500;
  
//   // Determine user-facing message
//   let userMessage;
//   if (error.userMessage) {
//     // Custom error classes provide user-friendly messages
//     userMessage = error.userMessage;
//   } else if (status >= 400 && status < 500) {
//     // For client errors, we can be more specific
//     userMessage = error.message || "Invalid request";
//   } else {
//     // For server errors, always use generic message
//     userMessage = "Internal server error";
//   }
  
//   response.status(status).json({ 
//     error: userMessage
//   });
// };

// export default errorHandler;
