var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;

// CVE-2026-41675: createProcessingInstruction does not validate its arguments (it does not
// throw InvalidCharacterError as the DOM spec requires), so a target or data containing "?>"
// is only rejected when the document is serialized with requireWellFormed: true
// (see test/dom/serializer.js).
// https://github.com/xmldom/xmldom/security/advisories/GHSA-x6wf-f3px-wcqx

vows.describe('Document.prototype.createProcessingInstruction').addBatch({
	'createProcessingInstruction accepts any target or data without throwing': function () {
		var doc = new DOMParser().parseFromString('<xml></xml>', 'text/xml');
		assert.doesNotThrow(function () {
			doc.createProcessingInstruction('ns:bad', 'data');
		});
		assert.doesNotThrow(function () {
			doc.createProcessingInstruction('xml', '?>');
		});
		assert.doesNotThrow(function () {
			doc.createProcessingInstruction('foo', 'inject?>evil');
		});
	},
	'createProcessingInstruction stores the target and data as is': function () {
		var doc = new DOMParser().parseFromString('<xml></xml>', 'text/xml');
		var pi = doc.createProcessingInstruction('foo', 'inject?>evil');
		assert.strictEqual(pi.nodeType, 7);
		assert.strictEqual(pi.target, 'foo');
		assert.strictEqual(pi.data, 'inject?>evil');
		assert.strictEqual(pi.nodeValue, 'inject?>evil');
	}
}).run();
