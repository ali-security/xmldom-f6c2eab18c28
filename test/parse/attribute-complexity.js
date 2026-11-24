var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;

// CVE-2026-83613: DOMHandler.startElement inserts every parsed attribute through
// setAttributeNode, and NamedNodeMap.setNamedItem de-duplicated each insert with the
// linear getNamedItem scan of the attributes already inserted, so a single well-formed
// element carrying M distinct attributes cost 1+2+...+M = O(M^2) comparisons in
// DOMParser.parseFromString() (and again in cloneNode/importNode, which copy the
// attributes through setAttributeNode). A nodeName membership index on the
// NamedNodeMap makes each insert O(1), so the element costs O(M).
// https://github.com/xmldom/xmldom/security/advisories/GHSA-8344-3jmq-59r6

// Growth ratio over a 4x increase in M: quadratic ~16x, linear ~4x. The threshold of 8
// (the log-space midpoint) separates the two with headroom and holds on slow CI.
var M1 = 4000;
var M2 = 16000; // 4x M1
var RATIO_MAX = 8;
var RUNS = 5;

/**
 * Returns the fastest wall-clock (ms) of `runs` executions of `fn`: the minimum is the
 * least noise-inflated sample, so a growth ratio built from two such measurements is
 * stable across fast and slow hosts.
 */
function fastestMs(fn, runs) {
	var best = Infinity;
	for (var k = 0; k < runs; k++) {
		var t = process.hrtime();
		fn();
		var d = process.hrtime(t);
		var ms = d[0] * 1e3 + d[1] / 1e6;
		if (ms < best) {
			best = ms;
		}
	}
	return best;
}

function attrBomb(m) {
	var parts = new Array(m);
	for (var i = 0; i < m; i++) {
		parts[i] = 'a' + i + '="x"';
	}
	return '<r ' + parts.join(' ') + '/>';
}

function parseXml(source) {
	return new DOMParser().parseFromString(source, 'text/xml');
}

function attrNames(el) {
	var names = [];
	for (var i = 0; i < el.attributes.length; i++) {
		names.push(el.attributes.item(i).nodeName);
	}
	return names.join(',');
}

var SPECIAL_NAMES = ['__proto__', 'constructor', 'hasOwnProperty', 'toString', 'valueOf',
	'nodeName', 'ownerElement', 'length', '_nameIndex'];

vows.describe('quadratic attribute de-duplication (GHSA-8344-3jmq-59r6)').addBatch({
	'an element with many distinct attributes parses in sub-quadratic time': function () {
		var xml1 = attrBomb(M1);
		var xml2 = attrBomb(M2);
		var t1 = fastestMs(function () { parseXml(xml1); }, RUNS);
		var t2 = fastestMs(function () { parseXml(xml2); }, RUNS);
		assert.ok(t2 / t1 < RATIO_MAX,
			'parse time grew ' + (t2 / t1).toFixed(1) + 'x (' + t1.toFixed(1) + 'ms -> ' +
			t2.toFixed(1) + 'ms) for a 4x attribute count, expected < ' + RATIO_MAX + 'x');
	},
	'an element with many distinct attributes clones in sub-quadratic time': function () {
		var el1 = parseXml(attrBomb(M1)).documentElement;
		var el2 = parseXml(attrBomb(M2)).documentElement;
		var t1 = fastestMs(function () { el1.cloneNode(false); }, RUNS);
		var t2 = fastestMs(function () { el2.cloneNode(false); }, RUNS);
		assert.ok(t2 / t1 < RATIO_MAX,
			'cloneNode time grew ' + (t2 / t1).toFixed(1) + 'x (' + t1.toFixed(1) + 'ms -> ' +
			t2.toFixed(1) + 'ms) for a 4x attribute count, expected < ' + RATIO_MAX + 'x');
	}
}).addBatch({
	'every parsed attribute is kept once, in source order': function () {
		var el = parseXml(attrBomb(M1)).documentElement;
		assert.equal(el.attributes.length, M1);
		for (var i = 0; i < M1; i += 97) {
			assert.equal(el.attributes.item(i).nodeName, 'a' + i);
			assert.equal(el.getAttributeNode('a' + i), el.attributes.item(i));
		}
	},
	'a duplicate parsed attribute is still reported and kept once': function () {
		var errors = [];
		var doc = new DOMParser({
			errorHandler: {
				warning: function () {},
				error: function (msg) { errors.push(msg); },
				fatalError: function (msg) { errors.push(msg); }
			}
		}).parseFromString('<r a="1" b="2" a="3"/>', 'text/xml');
		assert.ok(/Attribute a redefined/.test(errors.join('\n')), errors.join('\n'));
		// the lenient errorHandler lets the parse go on: the later value replaces the earlier
		assert.equal(attrNames(doc.documentElement), 'a,b');
		assert.equal(doc.documentElement.getAttribute('a'), '3');
	},
	'setAttribute on an existing name replaces it in place': function () {
		var el = parseXml('<r a="1" b="2" c="3"/>').documentElement;
		el.setAttribute('b', 'x');
		el.setAttribute('b', 'y');
		assert.equal(el.attributes.length, 3);
		assert.equal(attrNames(el), 'a,b,c');
		assert.equal(el.getAttribute('b'), 'y');
	},
	'setAttributeNode returns the replaced attribute and keeps a single entry': function () {
		var el = parseXml('<r a="1" b="2"/>').documentElement;
		var old = el.getAttributeNode('a');
		var attr = el.ownerDocument.createAttribute('a');
		attr.value = attr.nodeValue = 'new';
		assert.strictEqual(el.setAttributeNode(attr), old);
		assert.equal(el.attributes.length, 2);
		assert.strictEqual(el.getAttributeNode('a'), attr);
		assert.equal(attrNames(el), 'a,b');
		// a new name is appended and nothing is returned
		var c = el.ownerDocument.createAttribute('c');
		assert.strictEqual(el.setAttributeNode(c), undefined);
		assert.equal(attrNames(el), 'a,b,c');
	},
	'a removed attribute is re-added as a new entry': function () {
		var el = parseXml('<r a="1" b="2" c="3"/>').documentElement;
		el.removeAttribute('a');
		assert.equal(attrNames(el), 'b,c');
		assert.equal(el.hasAttribute('a'), false);
		el.setAttribute('a', '4');
		assert.equal(attrNames(el), 'b,c,a');
		el.setAttribute('a', '5');
		assert.equal(attrNames(el), 'b,c,a');
		assert.equal(el.getAttribute('a'), '5');
		el.removeAttributeNode(el.getAttributeNode('c'));
		el.removeAttribute('a');
		assert.equal(attrNames(el), 'b');
		el.setAttribute('c', '6');
		el.setAttribute('c', '7');
		assert.equal(attrNames(el), 'b,c');
		try {
			el.attributes.removeNamedItem('a');
		} catch (e) {
			assert.equal(e.code, 8);
			return;
		}
		assert.fail('removeNamedItem of a removed attribute did not throw');
	},
	'attributes named like Object.prototype or NamedNodeMap members are ordinary': function () {
		var source = '<r ' + SPECIAL_NAMES.map(function (name, i) {
			return name + '="' + i + '"';
		}).join(' ') + '/>';
		var el = parseXml(source).documentElement;
		assert.equal(attrNames(el), SPECIAL_NAMES.join(','));
		SPECIAL_NAMES.forEach(function (name, i) {
			assert.equal(el.getAttribute(name), String(i));
			el.setAttribute(name, 'v' + i);
		});
		assert.equal(attrNames(el), SPECIAL_NAMES.join(','));
		SPECIAL_NAMES.forEach(function (name, i) {
			assert.equal(el.getAttribute(name), 'v' + i);
		});
		// on an element without them, they are not reported as already present
		var fresh = el.ownerDocument.createElement('fresh');
		SPECIAL_NAMES.forEach(function (name) {
			var attr = el.ownerDocument.createAttribute(name);
			assert.strictEqual(fresh.setAttributeNode(attr), undefined, name);
		});
		assert.equal(attrNames(fresh), SPECIAL_NAMES.join(','));
		el.removeAttribute('__proto__');
		el.removeAttribute('constructor');
		assert.equal(attrNames(el), SPECIAL_NAMES.slice(2).join(','));
		el.setAttribute('__proto__', 'again');
		assert.equal(el.getAttribute('__proto__'), 'again');
		assert.equal(el.attributes.length, SPECIAL_NAMES.length - 1);
		assert.equal(typeof el.attributes.getNamedItem, 'function');
		assert.equal({}.nodeName, undefined);
	},
	'setAttributeNodeNS replacing a different nodeName keeps both names resolvable': function () {
		var doc = parseXml('<r/>');
		var el = doc.documentElement;
		var ax = doc.createAttributeNS('urn:a', 'a:x');
		el.setAttributeNodeNS(ax);
		// same namespaceURI and localName, other prefix: replaces a:x
		var bx = doc.createAttributeNS('urn:a', 'b:x');
		assert.strictEqual(el.setAttributeNodeNS(bx), ax);
		assert.equal(attrNames(el), 'b:x');
		assert.equal(el.getAttributeNode('a:x'), null);
		// a:x left the map: setting it again adds a new attribute
		el.setAttribute('a:x', '1');
		assert.equal(attrNames(el), 'b:x,a:x');
		// b:x is indexed: setting it replaces the namespaced attribute
		el.setAttribute('b:x', '2');
		assert.equal(attrNames(el), 'b:x,a:x');
		assert.equal(el.getAttribute('b:x'), '2');
	},
	'removing one of two attributes sharing a nodeName keeps the other replaceable': function () {
		var doc = parseXml('<r/>');
		var el = doc.documentElement;
		var p1 = doc.createAttributeNS('urn:1', 'p:x');
		var p2 = doc.createAttributeNS('urn:2', 'p:x');
		el.setAttributeNodeNS(p1);
		el.setAttributeNodeNS(p2);
		assert.equal(el.attributes.length, 2);
		el.removeAttributeNS('urn:2', 'x');
		assert.equal(el.attributes.length, 1);
		assert.strictEqual(el.attributes.item(0), p1);
		el.setAttribute('p:x', 'v');
		assert.equal(el.attributes.length, 1);
		assert.equal(el.getAttribute('p:x'), 'v');
	},
	'a clone has its own attribute index': function () {
		var el = parseXml('<r a="1" b="2"/>').documentElement;
		var clone = el.cloneNode(true);
		assert.equal(attrNames(clone), 'a,b');
		clone.setAttribute('a', 'c');
		clone.setAttribute('z', 'c');
		clone.removeAttribute('b');
		assert.equal(attrNames(clone), 'a,z');
		assert.equal(attrNames(el), 'a,b');
		assert.equal(el.getAttribute('a'), '1');
		el.setAttribute('b', '3');
		el.setAttribute('y', '4');
		assert.equal(attrNames(el), 'a,b,y');
		assert.equal(attrNames(clone), 'a,z');
		var imported = parseXml('<other/>').importNode(el, false);
		imported.setAttribute('a', '5');
		assert.equal(attrNames(imported), 'a,b,y');
		assert.equal(imported.getAttribute('a'), '5');
		assert.equal(el.getAttribute('a'), '1');
	}
}).run();
