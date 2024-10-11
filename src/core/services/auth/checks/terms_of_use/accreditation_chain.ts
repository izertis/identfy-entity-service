import {
  LazyChainOfResponsability
} from "../../../../../shared/classes/patterns/chain_of_responsability";
import {
  ChainHandler
} from "../../../../../shared/classes/utility/handler";
import {
  Result
} from "../../../../../shared/classes/utility/result";
import {
  ACCREDITATIONS_TYPES,
  EbsiAccreditationType
} from "../../../../../shared/constants/ebsi.constants";

export class ChainCheckAccreditationType extends LazyChainOfResponsability {
  private _types;
  constructor(types: string[]) {
    super();
    this._types = (
      types as EbsiAccreditationType[]).filter(
        (x) => (ACCREDITATIONS_TYPES).includes(x)
      );
  }

  collect(): Result<null, Error> {
    return super.collect(this._types);
  }

  public isAccreditation(): ChainCheckAccreditationType {
    this.addHandler(new class extends ChainHandler {
      handle(types: string[]): Result<null, Error> {
        if (!types.length) {
          return Result.Err(new Error(`Credential is not an accreditation`));
        }
        return Result.Ok(null);
      }

    });
    return this;
  }

  public notAccreditation(): ChainCheckAccreditationType {
    this.addHandler(new class extends ChainHandler {
      handle(types: string[]): Result<null, Error> {
        if (types.length) {
          return Result.Err(new Error(`Credential is an accreditation`));
        }
        return Result.Ok(null);
      }
    });
    return this;
  }

  public unique(): ChainCheckAccreditationType {
    this.addHandler(new class extends ChainHandler {
      handle(types: string[]): Result<null, Error> {
        if (types.length !== 1) {
          return Result.Err(
            new Error(
              `Invalid credential types. The VC have more than one accreditation type`
            )
          );
        }
        return Result.Ok(null);
      }
    });
    return this;
  }

  get types() {
    return this._types;
  }
}
