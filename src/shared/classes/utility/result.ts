export class Result<S, E extends Error | unknown> {
  protected constructor(
    protected ok: S | undefined,
    protected error: E | undefined,
  ) {}

  static Ok<S>(data: S): Result<S, any> {
    return new Result(data, undefined);
  }

  static Err<E>(data: E): Result<any, E> {
    return new Result(undefined, data);
  }

  isError() {
    return this.error !== undefined;
  }

  isOk() {
    return this.ok !== undefined;
  }

  unwrap(): S {
    if (this.isOk()) {
      return this.ok!;
    }
    throw new Error('Unwrap of error value');
  }

  unwrapError(): E {
    if (this.isError()) {
      return this.error!;
    }
    throw new Error('Unwrap of non error value');
  }

  map<N>(handler: (content: S) => N): Result<N, E> {
    if (this.isError()) {
      return Result.Err(this.error!);
    }
    return Result.Ok(handler(this.ok!));
  }

  consume(): S {
    if (this.isOk()) {
      return this.ok!;
    }
    throw this.error;
  }
}
