// Petri net execution state — matches Go internal/petri/fire.go exactly

export const ErrTransitionNotFound = () => new Error('transition not found');
export const ErrTransitionNotEnabled = () => new Error('transition not enabled');
export const ErrInsufficientTokens = () => new Error('insufficient tokens');

export class State {
  constructor(model) {
    this.model = model;
    this.marking = {};
    this.sequence = 0;

    // Initialize marking from model's initial values
    for (const p of model.places) {
      this.marking[p.id] = p.initial || 0;
    }
  }

  clone() {
    const s = new State(this.model);
    s.marking = { ...this.marking };
    s.sequence = this.sequence;
    return s;
  }

  tokens(placeID) {
    return this.marking[placeID] || 0;
  }

  setTokens(placeID, count) {
    this.marking[placeID] = count;
  }

  // Returns true if a transition can fire.
  // Checks all input arcs have tokens >= 1 (skips keyed arcs).
  enabled(transitionID) {
    const t = this.model.transitionByID(transitionID);
    if (!t) return false;

    for (const arc of this.model.inputArcs(transitionID)) {
      if (arc.keys && arc.keys.length > 0) continue;
      if ((this.marking[arc.source] || 0) < 1) return false;
    }

    return true;
  }

  enabledTransitions() {
    return this.model.transitions
      .filter(t => this.enabled(t.id))
      .map(t => t.id);
  }

  // Fire executes a transition, consuming and producing tokens.
  fire(transitionID) {
    if (!this.enabled(transitionID)) {
      throw ErrTransitionNotEnabled();
    }

    // Consume tokens from input places (skip keyed arcs)
    for (const arc of this.model.inputArcs(transitionID)) {
      if (arc.keys && arc.keys.length > 0) continue;
      this.marking[arc.source]--;
    }

    // Produce tokens at output places (skip keyed arcs)
    for (const arc of this.model.outputArcs(transitionID)) {
      if (arc.keys && arc.keys.length > 0) continue;
      this.marking[arc.target] = (this.marking[arc.target] || 0) + 1;
    }

    this.sequence++;
  }

  // BFS reachability check
  canReach(target, maxSteps = 1000) {
    const visited = new Set();
    const queue = [this.clone()];

    while (queue.length > 0 && maxSteps > 0) {
      const current = queue.shift();
      maxSteps--;

      const key = current._markingKey();
      if (visited.has(key)) continue;
      visited.add(key);

      if (current._matchesMarking(target)) return true;

      for (const tid of current.enabledTransitions()) {
        const next = current.clone();
        next.fire(tid);
        queue.push(next);
      }
    }

    return false;
  }

  _markingKey() {
    return this.model.places
      .map(p => `${p.id}:${this.marking[p.id] || 0}`)
      .join(';');
  }

  _matchesMarking(target) {
    for (const [k, v] of Object.entries(target)) {
      if ((this.marking[k] || 0) !== v) return false;
    }
    return true;
  }
}
