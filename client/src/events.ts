// A small typed event emitter that runs in browsers and Node alike.

export type Listener<T> = (value: T) => void;

export class Emitter<Events extends Record<string, unknown>> {
  private readonly listeners = new Map<PropertyKey, Set<Listener<never>>>();

  /** Returns a function that removes the listener. */
  on<K extends keyof Events>(event: K, listener: Listener<Events[K]>): () => void {
    let set = this.listeners.get(event);
    if (!set) this.listeners.set(event, (set = new Set()));
    set.add(listener as Listener<never>);
    return () => this.off(event, listener);
  }

  off<K extends keyof Events>(event: K, listener: Listener<Events[K]>): void {
    this.listeners.get(event)?.delete(listener as Listener<never>);
  }

  once<K extends keyof Events>(event: K, listener: Listener<Events[K]>): () => void {
    const off = this.on(event, (v) => {
      off();
      listener(v);
    });
    return off;
  }

  protected emit<K extends keyof Events>(event: K, value: Events[K]): void {
    for (const l of [...(this.listeners.get(event) ?? [])]) {
      try {
        (l as Listener<Events[K]>)(value);
      } catch (e) {
        // A throwing listener must not break protocol handling; surface it asynchronously.
        queueMicrotask(() => {
          throw e;
        });
      }
    }
  }
}
