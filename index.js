'use strict';

const Exports = {}

Exports.Cryptic = require('./cryptic.js');
Exports.Storage = require('./storage.js');

module.exports = Exports

/**
 * @typedef {import('./storage.js').CrypticStorage} Storage
 * @typedef {import('./cryptic.js').Cryptic} Cryptic
 * @typedef {import('./cryptic.js').CrypticInstance} CrypticInstance
 * @typedef {import('./cryptic.js').CrypticMethods} CrypticMethods
 */
