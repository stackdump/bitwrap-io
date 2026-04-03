// Petri net execution state — matches Go internal/metamodel/runtime.go
// Supports arc weights, variable bindings, keyed arcs, and read-arc detection.

export const ErrTransitionNotFound = () => new Error('transition not found');
export const ErrTransitionNotEnabled = () => new Error('transition not enabled');
export const ErrInsufficientTokens = () => new Error('insufficient tokens');

export class State {
  constructor(model) {
    this.model = model;
    this.tokens = {};   // scalar token counts (TokenState)
    this.data = {};     // map data (DataState)
    this.sequence = 0;

    // Initialize from model's initial values
    for (const p of model.places) {
      if (this._isMapType(p.schema)) {
        this.data[p.id] = {};
      } else {
        this.tokens[p.id] = p.initial || 0;
      }
    }
  }

  clone() {
    const s = new State(this.model);
    s.tokens = { ...this.tokens };
    s.data = {};
    for (const [k, v] of Object.entries(this.data)) {
      s.data[k] = this._deepCloneMap(v);
    }
    s.sequence = this.sequence;
    return s;
  }

  getTokens(placeID) {
    return this.tokens[placeID] || 0;
  }

  setTokens(placeID, count) {
    this.tokens[placeID] = count;
  }

  getDataMap(placeID) {
    if (!this.data[placeID]) this.data[placeID] = {};
    return this.data[placeID];
  }

  // Returns true if a transition can fire.
  // TokenState inputs: checks tokens >= arc weight (default 1).
  // DataState inputs: always enabled (data arcs don't block).
  enabled(transitionID) {
    const t = this.model.transitionByID(transitionID);
    if (!t) return false;

    for (const arc of this.model.inputArcs(transitionID)) {
      const place = this.model.placeByID(arc.source);
      if (!place) continue;
      if (this._isMapType(place.schema)) continue; // DataState: always enabled
      if (arc.keys && arc.keys.length > 0) continue; // keyed arcs managed by bindings
      if ((this.tokens[arc.source] || 0) < 1) return false;
    }

    return true;
  }

  enabledTransitions() {
    return this.model.transitions
      .filter(t => this.enabled(t.id))
      .map(t => t.id);
  }

  // Fire with Petri net semantics only (weight=1, no bindings).
  // For full colored net execution, use executeWithBindings.
  fire(transitionID) {
    if (!this.enabled(transitionID)) {
      throw ErrTransitionNotEnabled();
    }

    for (const arc of this.model.inputArcs(transitionID)) {
      if (arc.keys && arc.keys.length > 0) continue;
      const place = this.model.placeByID(arc.source);
      if (place && this._isMapType(place.schema)) continue;
      this.tokens[arc.source] = (this.tokens[arc.source] || 0) - 1;
    }

    for (const arc of this.model.outputArcs(transitionID)) {
      if (arc.keys && arc.keys.length > 0) continue;
      const place = this.model.placeByID(arc.target);
      if (place && this._isMapType(place.schema)) continue;
      this.tokens[arc.target] = (this.tokens[arc.target] || 0) + 1;
    }

    this.sequence++;
  }

  // Execute with variable bindings — matches Go metamodel.Runtime.ExecuteWithBindings.
  // Handles arc weights, keyed map access, and read-arc detection.
  executeWithBindings(transitionID, bindings) {
    if (!this.enabled(transitionID)) {
      throw ErrTransitionNotEnabled();
    }

    const inputArcs = this.model.inputArcs(transitionID);
    const outputArcs = this.model.outputArcs(transitionID);

    // Build output target set for read-arc detection
    const outputTargets = new Set();
    for (const arc of outputArcs) {
      outputTargets.add(arc.target + '|' + (arc.keys || []).join(','));
    }

    // Process input arcs
    for (const arc of inputArcs) {
      const place = this.model.placeByID(arc.source);
      if (!place) continue;

      // Skip read arcs (input+output to same keyed state)
      const inputKey = arc.source + '|' + (arc.keys || []).join(',');
      if (outputTargets.has(inputKey) && this._isMapType(place.schema)) {
        continue;
      }

      if (this._isMapType(place.schema)) {
        this._applyDataArc(arc.source, arc, bindings, false);
      } else {
        const w = this._arcWeight(arc, bindings);
        this.tokens[arc.source] = (this.tokens[arc.source] || 0) - w;
      }
    }

    // Process output arcs
    for (const arc of outputArcs) {
      const place = this.model.placeByID(arc.target);
      if (!place) continue;

      if (this._isMapType(place.schema)) {
        this._applyDataArc(arc.target, arc, bindings, true);
      } else {
        const w = this._arcWeight(arc, bindings);
        this.tokens[arc.target] = (this.tokens[arc.target] || 0) + w;
      }
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

  // --- Private helpers ---

  _arcWeight(arc, bindings) {
    const v = arc.value;
    if (!v) return 1;
    if (/^\d+$/.test(v)) return parseInt(v, 10);
    return parseInt(bindings[v], 10) || 0;
  }

  _applyDataArc(stateID, arc, bindings, add) {
    const valueName = arc.value || 'amount';
    const amount = parseInt(bindings[valueName], 10) || 0;
    const dataMap = this.getDataMap(stateID);
    const keys = arc.keys || [];

    if (keys.length === 0) return;

    if (keys.length === 1) {
      const key = String(bindings[keys[0]] || '');
      if (!key) return;
      const current = parseInt(dataMap[key], 10) || 0;
      dataMap[key] = add ? current + amount : current - amount;
      return;
    }

    if (keys.length === 2) {
      const key1 = String(bindings[keys[0]] || '');
      const key2 = String(bindings[keys[1]] || '');
      if (!key1 || !key2) return;
      if (!dataMap[key1] || typeof dataMap[key1] !== 'object') {
        dataMap[key1] = {};
      }
      const current = parseInt(dataMap[key1][key2], 10) || 0;
      dataMap[key1][key2] = add ? current + amount : current - amount;
    }
  }

  _isMapType(schema) {
    return schema && schema.startsWith('map[');
  }

  _markingKey() {
    return this.model.places
      .map(p => `${p.id}:${this.tokens[p.id] || 0}`)
      .join(';');
  }

  _matchesMarking(target) {
    for (const [k, v] of Object.entries(target)) {
      if ((this.tokens[k] || 0) !== v) return false;
    }
    return true;
  }

  _deepCloneMap(obj) {
    if (typeof obj !== 'object' || obj === null) return obj;
    const clone = {};
    for (const [k, v] of Object.entries(obj)) {
      clone[k] = typeof v === 'object' ? this._deepCloneMap(v) : v;
    }
    return clone;
  }
}
