export enum QueryOperator {
  Equal = 'EQ',
  NotEqual = 'NE',
  In = 'IN',
  NotIn = 'NIN',
  Greater = 'GT',
  GreaterEqual = 'GTE',
  Less = 'LT',
  LessEqual = 'LTE',
  Regex = 'RGX'
}

export enum SortKeywords {
  Ascending = 'ASC',
  Descending = 'DESC'
}

export enum PaginationError {
  PageMandatory = 'pagination.PAGE_MANDATORY',
  SizeMandatory = 'pagination.SIZE_MANDATORY',
  PageFormat = 'pagination.PAGE_FORMAT',
  SizeFormat = 'pagination.SIZE_FORMAT',
  SortOrderFormat = 'pagination.SORT_ORDER_FORMAT'
}

export enum PaginationDefault {
  MinPage = 0,
  MaxSize = 100
}

export const QueryKeywords = ['page', 'size', 'sort', 'search']
