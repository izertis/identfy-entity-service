export class Stack<T> {
  protected memory: T[] = [];

  push(item: T) {
    this.memory.push(item);
  }

  pop(): T | undefined {
    return this.memory.pop();
  }

  peek(): T | undefined {
    return this.memory[this.memory.length - 1];
  }

  isEmpty(): boolean {
    return this.memory.length === 0;
  }

  size(): number {
    return this.memory.length;
  }

  clear(): void {
    this.memory = [];
  }
}
