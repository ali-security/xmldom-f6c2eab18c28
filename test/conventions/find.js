var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;
// `find` is private to dom.js, it is only exported for this test
var find = require('xmldom/dom').__find;

// CVE-2022-39353: the pre-insertion validity checks that keep a Document to a
// single root element look up element and doctype children with this
// `Array.prototype.find` ponyfill, so it has to work on runtimes without
// `Array.prototype.find` (like node 0.10) and on NodeList.
// https://github.com/xmldom/xmldom/security/advisories/GHSA-crh6-fp67-6883

function recordingPredicate(match) {
	var calls = [];
	function predicate(item, index, list) {
		calls.push([item, index, list]);
		return item === match;
	}
	predicate.calls = calls;
	return predicate;
}

function assertCalledWith(predicate, callIndex, item, index, list) {
	var call = predicate.calls[callIndex];
	assert.ok(call, 'predicate was not called a ' + (callIndex + 1) + '. time');
	assert.strictEqual(call[0], item);
	assert.strictEqual(call[1], index);
	assert.strictEqual(call[2], list);
}

vows.describe('find').addBatch({
	'should work in node without passing an ArrayConstructor': function () {
		var predicate = recordingPredicate('b');
		var list = ['a', 'b', 'c'];

		assert.strictEqual(find(list, predicate), 'b');
		assert.strictEqual(predicate.calls.length, 2);
		assertCalledWith(predicate, 0, 'a', 0, list);
		assertCalledWith(predicate, 1, 'b', 1, list);
	},
	'should work when ArrayConstructor does not provide find': function () {
		var predicate = recordingPredicate('b');
		var list = ['a', 'b', 'c'];

		assert.strictEqual(find(list, predicate, {}), 'b');
		assert.strictEqual(predicate.calls.length, 2);
		assertCalledWith(predicate, 0, 'a', 0, list);
		assertCalledWith(predicate, 1, 'b', 1, list);
	},
	'should use the find of the passed ArrayConstructor': function () {
		var list = ['a', 'b', 'c'];
		var received = null;
		var ac = {
			find: function (predicate) {
				received = {self: this, predicate: predicate};
				return 'custom';
			}
		};
		var predicate = recordingPredicate('b');

		assert.strictEqual(find(list, predicate, ac), 'custom');
		assert.strictEqual(received.self, list);
		assert.strictEqual(received.predicate, predicate);
		assert.strictEqual(predicate.calls.length, 0);
	},
	'should work with an array-like object when ArrayConstructor does not provide find': function () {
		var predicate = recordingPredicate('b');
		var list = {length: 3, 0: 'a', 1: 'b', 2: 'c'};

		assert.strictEqual(find(list, predicate, {}), 'b');
		assert.strictEqual(predicate.calls.length, 2);
		assertCalledWith(predicate, 0, 'a', 0, list);
		assertCalledWith(predicate, 1, 'b', 1, list);
	},
	'should return undefined when no item matches': function () {
		var predicate = recordingPredicate('x');
		var list = ['a', 'b', 'c'];

		assert.strictEqual(find(list, predicate), undefined);
		assert.strictEqual(predicate.calls.length, 3);
		assert.strictEqual(find(list, recordingPredicate('x'), {}), undefined);
	},
	'should work on a NodeList': function () {
		var doc = new DOMParser().parseFromString('<!--c--><root/>', 'text/xml');
		var childNodes = doc.childNodes;
		function isElement(node) {
			return node.nodeType === 1;
		}

		assert.strictEqual(find(childNodes, isElement), doc.documentElement);
		assert.strictEqual(find(childNodes, isElement, {}), doc.documentElement);
	}
}).run();
