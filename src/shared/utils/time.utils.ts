export async function wait(ms: number) {
  return new Promise((sucess, _error) => {
    setTimeout(sucess, ms)
  });
}
