/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable prefer-const */
/* eslint-disable @typescript-eslint/no-explicit-any */
import {
  PaginationDefault,
  PaginationError,
  QueryKeywords,
  QueryOperator,
  SortKeywords,
} from "../constants/query.constants.js";
import { BadRequestError } from "./errors.js";

export class QueryStatement {
  constructor(public field: string, public operator: QueryOperator, public value: any) { }

  setField = (field: string) => {
    this.field = field;
    return this;
  };

  setOperator = (operator: QueryOperator) => {
    this.operator = operator;
    return this;
  };

  setValue = (value: any) => {
    this.value = value;
    return this;
  };

  static createFromObject = (data: any): QueryStatement | QueryStatement[] => {
    const [field, query] = data;
    if (!(query instanceof Object) && QueryStatement.valueIsQueryable(query)) {
      return new QueryStatement(field, QueryOperator.Equal, query);
    }
    return QueryStatement.parseQueryEntries(query)
      .filter(([operator, value]) => QueryStatement.valueIsQueryable(value))
      .map(([operator, value]) => new QueryStatement(field, operator, value));
  };

  private static valueIsQueryable = (value: any) =>
    [
      value === null,
      value === undefined,
      value === "null",
      value === "undefined",
      Array.isArray(value) && value.length === 0,
    ].every((condition) => !condition);

  private static parseQueryEntries = (data: object) =>
    Object.entries(data).map((entry) => {
      let [operator, value] = entry;

      if (operator === QueryOperator.In || operator === QueryOperator.NotIn) {
        value = value ? value.split(",") : [];
      }
      return [operator, value];
    });
}

export class QueryFilter {
  public statements: QueryStatement[] = [];

  constructor(filter: QueryStatement[] | QueryType) {
    this.statements =
      filter instanceof Array
        ? (this.statements = filter)
        : (this.statements = QueryFilter.createFromObject(filter).statements);
  }

  addStatement = (field: string, operator: QueryOperator, value: any) => {
    const statement = new QueryStatement(field, operator, value);
    const index = this.statements.findIndex((statement) => statement.field === field);
    if (index !== -1) {
      console.warn(`Field "${field}" already exists inside filter`);
      console.warn(`Only last statement will remain`);
      this.statements[index] = statement;
    } else {
      this.statements.push(new QueryStatement(field, operator, value));
    }
    return this;
  };

  getFields = () => Array.from(new Set(this.statements.map((stmt) => stmt.field)));

  static createFromObject = (filter: any) => {
    QueryKeywords.forEach((field: any) => delete filter[field]);

    const statements = Object.entries(filter)
      .flatMap((entry) => QueryStatement.createFromObject(entry))
      .filter((statement) => statement);
    return new QueryFilter(statements);
  };
}

export class QueryPagination {
  public skip = 0;
  public limit = Number.MAX_SAFE_INTEGER;
  public search = "";
  public sort!: {
    order: number | null;
    field: string | null;
  };
  public pageable!: Pagination;

  constructor(data: Pagination, strict: boolean) {
    this.validate(data);
    this.compose(data, strict);
  }

  private validate = (data: Pagination) => {
    let { page, size, sort } = data;
    const sortData = sort?.split(",") ?? [];
    page = page ? Number.parseInt(page as string) : null;
    size = page ? Number.parseInt(size as string) : null;

    if (page && Number.isNaN(page)) {
      throw new BadRequestError(PaginationError.PageFormat, "Invalid page");
    }
    if (size && Number.isNaN(size)) {
      throw new BadRequestError(PaginationError.SizeFormat, "Invalid size");
    }
    if (sortData.length > 1) {
      const [sortField, sortOrder] = sortData;

      if (!Object.values(SortKeywords).includes(sortOrder as SortKeywords)) {
        throw new BadRequestError(PaginationError.SortOrderFormat, "Invalid sort order format");
      }
    }
  };

  private compose = (data: Pagination, strict: boolean) => {
    let { page, size, sort, search } = data;
    if (strict && !page) page = PaginationDefault.MinPage;
    if (strict && !size) size = PaginationDefault.MaxSize;

    page = Number.parseInt(page as string);
    size = Number.parseInt(size as string);
    const sortData = sort?.split(",") ?? [];

    this.sort = { order: null, field: null };
    this.skip = page && size ? page * size : 0;
    this.limit = size ? size : Number.MAX_SAFE_INTEGER;
    this.search = search ?? "";

    if (sortData.length) {
      let [field, order] = sortData;
      this.sort = { field: field ?? null, order: order === SortKeywords.Descending ? -1 : 1 };
    }
    this.pageable = { ...data };
  };
}

export interface Pagination {
  page?: string | number | null;
  size?: string | number | null;
  sort?: string;
  search?: string;
}

export interface Sort {
  empty: boolean;
  sorted: boolean;
  unsorted: boolean;
}

type QueryObject = { [key in QueryOperator]?: any };

export type QueryType = { [key: string]: QueryObject } | { [key: string]: any };
