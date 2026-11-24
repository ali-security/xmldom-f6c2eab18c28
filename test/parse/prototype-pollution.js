var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;

// CVE-2022-37616: the SAX parser in sax.js copied namespace maps with _copy()
// and ended prefix mappings by iterating every enumerable property, including
// the ones inherited from Object.prototype, so a polluted Object.prototype
// became a namespace binding and a prefix mapping reported to the domBuilder.

var hasOwn = Object.prototype.hasOwnProperty;

// a domBuilder that records the elements and ended prefix mappings it receives
function recordingBuilder() {
	var builder = {elements: [], endedPrefixes: [], errors: []};
	function noop() {}
	builder.startDocument = builder.endDocument = builder.endElement = noop;
	builder.startPrefixMapping = builder.characters = builder.ignorableWhitespace = noop;
	builder.processingInstruction = builder.comment = noop;
	builder.startCDATA = builder.endCDATA = builder.startDTD = builder.endDTD = noop;
	builder.startElement = function (namespaceURI, localName, qName, el) {
		builder.elements.push(el);
	};
	builder.endPrefixMapping = function (prefix) {
		builder.endedPrefixes.push(prefix);
	};
	builder.warning = builder.error = builder.fatalError = function (msg) {
		builder.errors.push(msg);
	};
	return builder;
}

// parses source while Object.prototype carries an enumerable `polluted` property
function parseWithPollutedPrototype(source) {
	var builder = recordingBuilder();
	Object.prototype.polluted = 'urn:polluted';
	try {
		new DOMParser({domBuilder: builder}).parseFromString(source, 'text/xml');
	} finally {
		delete Object.prototype.polluted;
	}
	assert.deepEqual(builder.errors, []);
	return builder;
}

vows.describe('prototype pollution (sax)').addBatch({
	'endPrefixMapping is only reported for declared prefixes': function () {
		var builder = parseWithPollutedPrototype('<root xmlns:a="urn:a"><a:child xmlns:b="urn:b"/></root>');
		// b ends with the self-closed child element, a with the end tag of root
		assert.deepEqual(builder.endedPrefixes, ['b', 'a']);
	},
	'copied namespace maps do not receive inherited properties': function () {
		var builder = parseWithPollutedPrototype('<root><child xmlns:a="urn:a"></child></root>');
		assert.equal(builder.elements.length, 2);
		// root declares no namespace, so it keeps the copy of the default namespace map
		var defaultNSMap = builder.elements[0].currentNSMap;
		assert.ok(hasOwn.call(defaultNSMap, 'xml'));
		assert.ok(!hasOwn.call(defaultNSMap, 'polluted'), 'inherited property copied into the default namespace map');
		// child declares a namespace, so it gets a map inheriting the parent's namespace map
		// through the prototype chain, instead of a flat copy (GHSA-965w-775f-mr7g)
		var childNSMap = builder.elements[1].currentNSMap;
		assert.ok(hasOwn.call(childNSMap, 'a'));
		assert.equal(childNSMap.a, 'urn:a');
		assert.strictEqual(Object.getPrototypeOf(childNSMap), defaultNSMap);
		assert.equal(childNSMap.xml, 'http://www.w3.org/XML/1998/namespace');
		assert.ok(!hasOwn.call(childNSMap, 'polluted'), 'inherited property copied into the element namespace map');
	}
}).run();
