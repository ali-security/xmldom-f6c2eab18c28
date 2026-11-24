var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;

// CVE-2022-37616: copy(), cloneNode(), lookupPrefix() and lookupNamespaceURI()
// in dom.js used every enumerable property of an object, including the ones
// inherited from Object.prototype, so a polluted Object.prototype leaked into
// the DOM as own properties or as namespace bindings.

var hasOwn = Object.prototype.hasOwnProperty;

// runs fn while Object.prototype carries an enumerable `polluted` property
function withPollutedPrototype(value, fn) {
	Object.prototype.polluted = value;
	try {
		return fn();
	} finally {
		delete Object.prototype.polluted;
	}
}

function parse(source) {
	return new DOMParser().parseFromString(source, 'text/xml');
}

vows.describe('prototype pollution (dom)').addBatch({
	'copy() does not copy inherited properties onto a live node list': function () {
		var doc = parse('<root><a/><a/></root>');
		var list = withPollutedPrototype('yes', function () {
			return doc.documentElement.getElementsByTagName('a');
		});
		assert.ok(!hasOwn.call(list, 'polluted'), 'inherited property copied onto the node list');
		assert.equal(list.length, 2);
		assert.equal(list.item(0).tagName, 'a');
		assert.equal(list.item(1).tagName, 'a');
	},
	'cloneNode() does not copy inherited properties onto the clone': function () {
		var doc = parse('<root attr="1"><child>text</child></root>');
		// NaN never equals the value the clone inherits, so the inherited
		// property is not skipped as an unchanged value
		var clone = withPollutedPrototype(NaN, function () {
			return doc.documentElement.cloneNode(true);
		});
		assert.ok(!hasOwn.call(clone, 'polluted'), 'element clone');
		assert.ok(!hasOwn.call(clone.getAttributeNode('attr'), 'polluted'), 'attribute clone');
		assert.ok(!hasOwn.call(clone.firstChild, 'polluted'), 'child element clone');
		assert.ok(!hasOwn.call(clone.firstChild.firstChild, 'polluted'), 'text clone');
		assert.equal(clone.toString(), '<root attr="1"><child>text</child></root>');
	},
	'lookupPrefix() ignores inherited properties of the namespace map': function () {
		var root = parse('<root xmlns:a="urn:a"/>').documentElement;
		var prefix = withPollutedPrototype('urn:polluted', function () {
			return root.lookupPrefix('urn:polluted');
		});
		assert.strictEqual(prefix, null);
		assert.equal(root.lookupPrefix('urn:a'), 'a');
	},
	'lookupNamespaceURI() ignores inherited properties of the namespace map': function () {
		var root = parse('<root xmlns:a="urn:a"/>').documentElement;
		var uri = withPollutedPrototype('urn:polluted', function () {
			return root.lookupNamespaceURI('polluted');
		});
		assert.strictEqual(uri, null);
		assert.strictEqual(root.lookupNamespaceURI('constructor'), null);
		assert.strictEqual(root.lookupNamespaceURI('toString'), null);
		assert.strictEqual(root.lookupNamespaceURI('__proto__'), null);
		assert.equal(root.lookupNamespaceURI('a'), 'urn:a');
	}
}).run();
