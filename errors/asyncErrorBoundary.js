// const asyncErrorBoundary = (delegate, defaultStatus = 500, context = "Unknown operation") => {
//   return (request, response, next) => {
//     Promise.resolve()
//       .then(() => delegate(request, response, next))
//       .catch((error = {}) => {
//         const { status = defaultStatus, message = "Something went wrong!" } = error;
        
//         // If it's a generic error (no custom message), add context
//         if (message === "Something went wrong!" || !error.message) {
//           error.message = `Internal server error during ${context}. Please try again later.`;
//         }
        
//         next({
//           status,
//           message: error.message,
//         });
//       });
//   };
// }

// export default asyncErrorBoundary;

const asyncErrorBoundary = (delegate, defaultStatus = 500, context = "Unknown operation") => {
  return (request, response, next) => {
    Promise.resolve()
      .then(() => delegate(request, response, next))
      .catch((error = {}) => {
        const { status = defaultStatus, message = "Something went wrong!" } = error;
        
        // Enhanced logging with context
        console.error(`Error in ${context}:`, {
          originalError: error,
          stack: error.stack,
          url: request.originalUrl,
          method: request.method,
          body: request.body,
          timestamp: new Date().toISOString()
        });
        
        // If it's a generic error (no custom message), add context
        if (message === "Something went wrong!" || !error.message) {
          error.message = `Internal server error during ${context}. Please try again later.`;
        }
        
        next({
          status,
          message: error.message,
        });
      });
  };
}

export default asyncErrorBoundary;

