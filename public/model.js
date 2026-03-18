// Petri net model types — matches Go internal/petri/model.go exactly

// Validation errors
export const ErrEmptyID = () => new Error('empty ID');
export const ErrDuplicateID = () => new Error('duplicate ID');
export const ErrInvalidArcSource = () => new Error('invalid arc source');
export const ErrInvalidArcTarget = () => new Error('invalid arc target');
export const ErrInvalidArcConnection = () => new Error('invalid arc connection: must connect place to transition or vice versa');

export class Model {
  constructor(name, version = '1.0.0') {
    this.name = name;
    this.version = version;
    this.places = [];
    this.transitions = [];
    this.arcs = [];
    this.invariants = [];
  }

  addPlace(place) {
    this.places.push({ id: '', schema: '', initial: 0, exported: false, ...place });
    return this;
  }

  addTransition(transition) {
    this.transitions.push({ id: '', guard: '', ...transition });
    return this;
  }

  addArc(arc) {
    this.arcs.push({ source: '', target: '', keys: [], value: '', ...arc });
    return this;
  }

  addInvariant(invariant) {
    this.invariants.push({ id: '', expr: '', ...invariant });
    return this;
  }

  placeByID(id) {
    return this.places.find(p => p.id === id) || null;
  }

  placeIsExported(id) {
    const p = this.placeByID(id);
    return p ? p.exported : false;
  }

  transitionByID(id) {
    return this.transitions.find(t => t.id === id) || null;
  }

  inputArcs(transitionID) {
    return this.arcs.filter(a => a.target === transitionID);
  }

  outputArcs(transitionID) {
    return this.arcs.filter(a => a.source === transitionID);
  }

  validate() {
    const placeIDs = new Set();
    const transitionIDs = new Set();

    for (const p of this.places) {
      if (!p.id) throw ErrEmptyID();
      if (placeIDs.has(p.id)) throw ErrDuplicateID();
      placeIDs.add(p.id);
    }

    for (const t of this.transitions) {
      if (!t.id) throw ErrEmptyID();
      if (transitionIDs.has(t.id)) throw ErrDuplicateID();
      transitionIDs.add(t.id);
    }

    for (const a of this.arcs) {
      const sourceIsPlace = placeIDs.has(a.source);
      const sourceIsTransition = transitionIDs.has(a.source);
      const targetIsPlace = placeIDs.has(a.target);
      const targetIsTransition = transitionIDs.has(a.target);

      if (!sourceIsPlace && !sourceIsTransition) throw ErrInvalidArcSource();
      if (!targetIsPlace && !targetIsTransition) throw ErrInvalidArcTarget();
      if (sourceIsPlace && targetIsPlace) throw ErrInvalidArcConnection();
      if (sourceIsTransition && targetIsTransition) throw ErrInvalidArcConnection();
    }

    return true;
  }
}
