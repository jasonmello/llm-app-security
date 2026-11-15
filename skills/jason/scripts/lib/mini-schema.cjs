'use strict';
// Minimal JSON Schema validator: supports only the keywords used by this
// skill's templates (type, const, enum, required, properties,
// additionalProperties:false, items, minItems, minLength, pattern, minimum,
// format: date-time).
// Zero dependencies so the skill works anywhere Node runs.

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (Number.isInteger(v)) return 'integer';
  return typeof v;
}

const SUPPORTED = new Set(['$schema', 'title', 'description', 'type', 'const', 'enum', 'required',
  'properties', 'additionalProperties', 'items', 'minItems', 'minLength', 'pattern', 'minimum', 'format']);

function validate(schema, value, path = '$', errors = []) {
  for (const k of Object.keys(schema)) {
    if (!SUPPORTED.has(k)) throw new Error(`mini-schema: unsupported keyword "${k}" at ${path}`);
  }
  if (schema.format && schema.format !== 'date-time') throw new Error(`mini-schema: unsupported format "${schema.format}"`);
  if ('const' in schema && value !== schema.const) {
    errors.push(`${path}: must equal ${JSON.stringify(schema.const)}`);
  }
  if (schema.enum && !schema.enum.includes(value)) {
    errors.push(`${path}: must be one of ${schema.enum.join(', ')}`);
  }
  if (schema.type) {
    const t = typeOf(value);
    const ok = schema.type === t || (schema.type === 'number' && t === 'integer');
    if (!ok) {
      errors.push(`${path}: expected ${schema.type}, got ${t}`);
      return errors;
    }
  }
  if (typeof value === 'string') {
    if (schema.minLength != null && value.length < schema.minLength) {
      errors.push(`${path}: shorter than ${schema.minLength}`);
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${path}: does not match ${schema.pattern}`);
    }
    if (schema.format === 'date-time' &&
        !(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(value) && !Number.isNaN(Date.parse(value)))) {
      errors.push(`${path}: not an RFC 3339 date-time`);
    }
  }
  if (typeof value === 'number' && schema.minimum != null && value < schema.minimum) {
    errors.push(`${path}: below minimum ${schema.minimum}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems != null && value.length < schema.minItems) {
      errors.push(`${path}: needs at least ${schema.minItems} item(s)`);
    }
    if (schema.items) value.forEach((v, i) => validate(schema.items, v, `${path}[${i}]`, errors));
  }
  if (typeOf(value) === 'object') {
    for (const key of schema.required || []) {
      if (!(key in value)) errors.push(`${path}: missing "${key}"`);
    }
    const props = schema.properties || {};
    for (const [key, v] of Object.entries(value)) {
      if (props[key]) validate(props[key], v, `${path}.${key}`, errors);
      else if (schema.additionalProperties === false) errors.push(`${path}: unexpected "${key}"`);
    }
  }
  return errors;
}

module.exports = { validate };
