// Custom error classes for better error handling
export class ValidationError extends Error {
  constructor(message, userMessage = "Invalid data provided") {
    super(message);
    this.name = 'ValidationError';
    this.status = 400;
    this.userMessage = userMessage;
  }
}

export class AuthenticationError extends Error {
  constructor(message, userMessage = "Authentication failed") {
    super(message);
    this.name = 'AuthenticationError';
    this.status = 401;
    this.userMessage = userMessage;
  }
}

export class AuthorizationError extends Error {
  constructor(message, userMessage = "Access denied") {
    super(message);
    this.name = 'AuthorizationError';
    this.status = 403;
    this.userMessage = userMessage;
  }
}

export class NotFoundError extends Error {
  constructor(message, userMessage = "Resource not found") {
    super(message);
    this.name = 'NotFoundError';
    this.status = 404;
    this.userMessage = userMessage;
  }
}

export class ConflictError extends Error {
  constructor(message, userMessage = "Resource conflict") {
    super(message);
    this.name = 'ConflictError';
    this.status = 409;
    this.userMessage = userMessage;
  }
}

export class RateLimitError extends Error {
  constructor(message, userMessage = "Too many requests") {
    super(message);
    this.name = 'RateLimitError';
    this.status = 429;
    this.userMessage = userMessage;
  }
}

export class InternalServerError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InternalServerError';
    this.status = 500;
    this.userMessage = "Internal server error";
  }
} 