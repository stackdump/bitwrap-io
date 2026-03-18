// Schema <-> Model bridge — matches Go internal/petri/bridge.go exactly

import { Model } from './model.js';

// Convert a metamodel Schema to a Petri net Model
export function fromSchema(schema) {
  const m = new Model(schema.name || '', schema.version || '1.0.0');

  if (schema.states) {
    for (const st of schema.states) {
      m.addPlace({
        id: st.id,
        schema: st.type || '',
        initial: toInt(st.initial),
        exported: st.exported || false,
      });
    }
  }

  if (schema.actions) {
    for (const a of schema.actions) {
      m.addTransition({
        id: a.id,
        guard: a.guard || '',
      });
    }
  }

  if (schema.arcs) {
    for (const arc of schema.arcs) {
      m.addArc({
        source: arc.source,
        target: arc.target,
        keys: arc.keys || [],
        value: arc.value || '',
      });
    }
  }

  if (schema.constraints) {
    for (const c of schema.constraints) {
      m.addInvariant({
        id: c.id,
        expr: c.expr || '',
      });
    }
  }

  return m;
}

// Convert a Petri net Model to a metamodel Schema
export function toSchema(model) {
  return {
    name: model.name,
    version: model.version,
    states: model.places.map(p => ({
      id: p.id,
      type: p.schema || undefined,
      initial: p.initial || undefined,
      exported: p.exported || undefined,
    })),
    actions: model.transitions.map(t => ({
      id: t.id,
      guard: t.guard || undefined,
    })),
    arcs: model.arcs.map(a => ({
      source: a.source,
      target: a.target,
      keys: a.keys && a.keys.length > 0 ? a.keys : undefined,
      value: a.value || undefined,
    })),
    constraints: model.invariants.map(inv => ({
      id: inv.id,
      expr: inv.expr,
    })),
  };
}

// Type converters matching Go bridge.go

export function stateToPlace(st) {
  return {
    id: st.id,
    schema: st.type || '',
    initial: toInt(st.initial),
    exported: st.exported || false,
  };
}

export function placeToState(p) {
  return {
    id: p.id,
    type: p.schema || '',
    initial: p.initial || 0,
    exported: p.exported || false,
  };
}

export function actionToTransition(a) {
  return { id: a.id, guard: a.guard || '' };
}

export function transitionToAction(t) {
  return { id: t.id, guard: t.guard || '' };
}

export function constraintToInvariant(c) {
  return { id: c.id, expr: c.expr || '' };
}

export function invariantToConstraint(inv) {
  return { id: inv.id, expr: inv.expr || '' };
}

// Helper: coerce initial value to int (handles int, float, null)
function toInt(v) {
  if (v == null) return 0;
  return Math.floor(Number(v));
}
