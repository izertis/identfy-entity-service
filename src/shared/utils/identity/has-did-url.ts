export interface HasDidUrl {
  getDidUrl(): string;
}

export function isSameDidUrlOrDerived(
  first: string | HasDidUrl,
  second: string | HasDidUrl,
) {
  const firstDidUrl = toDidUrl(first);
  const secondDidUrl = toDidUrl(second);

  return secondDidUrl.startsWith(firstDidUrl);
}

function toDidUrl(id: string | HasDidUrl) {
  if (typeof id === 'string') {
    return id;
  } else {
    return id.getDidUrl();
  }
}
