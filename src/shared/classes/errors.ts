import statuses, { HttpStatus } from 'http-status';

export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    public message: string,
  ) {
    super();
    this.message = message ?? statuses[status as keyof HttpStatus];
  }
}

export class BadRequestError extends HttpError {
  constructor(
    public message: string,
    public code: string
  ) {
    super(statuses.BAD_REQUEST, message, code);
  }
}

export class UnauthorizedError extends HttpError {
  constructor(
    public message: string,
    public code: string
  ) {
    super(statuses.UNAUTHORIZED, message, code);
  }
}

export class NotFoundError extends HttpError {
  constructor(
    public message: string,
    public code: string
  ) {
    super(statuses.NOT_FOUND, message, code);
  }
}

export class ConflictError extends HttpError {
  constructor(
    public message: string,
    public code: string
  ) {
    super(statuses.CONFLICT, message, code);
  }
}

export class UnsupportedMediaTypeError extends HttpError {
  constructor(
    public message: string,
    public code: string
  ) {
    super(statuses.UNSUPPORTED_MEDIA_TYPE, message, code);
  }
}

export class UnprocessableEntityError extends HttpError {
  constructor(
    public message: string,
    public code: string
  ) {
    super(statuses.UNPROCESSABLE_ENTITY, message, code);
  }
}

export class InternalServerError extends HttpError {
  constructor(
    public message: string,
    public code: string
  ) {
    super(statuses.INTERNAL_SERVER_ERROR, message, code);
  }
}

export class ServiceUnavailableError extends HttpError {
  constructor(
    public message: string,
    public code: string
  ) {
    super(statuses.SERVICE_UNAVAILABLE, message, code);
  }
}
