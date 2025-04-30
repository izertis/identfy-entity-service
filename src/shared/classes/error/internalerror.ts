export class UnsupportedJWA extends Error {
  constructor(kty: string) {
    super(`Unsupported JWA alg indicated in JWT Header: ${kty}`);
  }
}

export class UnsupportedKty extends Error {
  constructor(kty: string) {
    super(`Unsupported keys type used: ${kty}`);
  }
}

export class InvalidConfigurationResolver extends Error {
  constructor(msg: string) {
    super(`Invalid configuration provided: ${msg}`);
  }
}

export class DidResolutionError extends Error {
  constructor(msg: string) {
    super(`Invalid DID Resolution: ${msg}`);
  }
}

export class ErrorType extends Error {
  name: string;
  message: string;
  cause?: string;

  constructor(name: string, message: string, cause?: string) {
      super();
      this.name = name;
      this.message = message;
      this.cause = cause;
  }
}

export class OpenIDError extends ErrorType {
  constructor(message: string, cause?: string) {
      super("OpenID Error", message, cause);
  }
}

export class InfallibleError extends ErrorType {
  constructor(message: string, cause?: string) {
      super("Infallible", message, cause);
  }
}

export class JwsError extends ErrorType {
  constructor(message: string, cause?: string) {
      super("JWKs Error", message, cause);
  }
}

export class ExecutionFailed extends ErrorType {
  constructor(message: string, cause?: string) {
      super("Execution failed", message, cause);
  }
}

export class InvalidParameters extends ErrorType {
  constructor(message: string, cause?: string) {
      super("Invalid Parameters Provided", message, cause);
  }
}

export class FetchError extends ErrorType {
  constructor(message: string, cause?: string) {
      super("Fetch Error", message, cause);
  }
}

export class InvalidSigningAlg extends ErrorType {
  constructor(message: string, cause?: string) {
      super("Invalid Singing Algorithm", message, cause);
  }
}
