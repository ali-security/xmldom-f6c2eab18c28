var vows = require('vows');
var assert = require('assert');
var DOMImplementation = require('xmldom/dom').DOMImplementation;
// `walkDOM` is private to dom.js, it is only exported for this test
var walkDOM = require('xmldom/dom').__walkDOM;

// CVE-2026-41673: normalize(), serializeToString(), cloneNode(), importNode(), textContent
// and the getElement(s)By* lookups walk the tree with this iterative `walkDOM` helper
// instead of recursing once per nesting level. These vows port upstream's
// test/dom/walk-dom.test.js to ES5 vows (node 0.10).
// https://github.com/xmldom/xmldom/security/advisories/GHSA-2v35-w6hq-6mfw

/**
 * Build a small DOM tree for testing:
 *
 *   root (Element)
 *     childA (Element)
 *       grandchildA1 (Element)
 *       grandchildA2 (Element)
 *     childB (Element)
 *       grandchildB1 (Element)
 */
function buildTree() {
	var impl = new DOMImplementation();
	var doc = impl.createDocument(null, 'root');
	var root = doc.documentElement;

	var childA = doc.createElement('childA');
	root.appendChild(childA);
	var grandchildA1 = doc.createElement('grandchildA1');
	childA.appendChild(grandchildA1);
	var grandchildA2 = doc.createElement('grandchildA2');
	childA.appendChild(grandchildA2);
	var childB = doc.createElement('childB');
	root.appendChild(childB);
	var grandchildB1 = doc.createElement('grandchildB1');
	childB.appendChild(grandchildB1);

	return {
		doc: doc,
		root: root,
		childA: childA,
		grandchildA1: grandchildA1,
		grandchildA2: grandchildA2,
		childB: childB,
		grandchildB1: grandchildB1
	};
}

function skipChildrenOfChildA(skipValue) {
	var root = buildTree().root;
	var visited = [];
	walkDOM(root, null, {
		enter: function (node) {
			visited.push(node.nodeName);
			if (node.nodeName === 'childA') {
				return skipValue; // skip grandchildA1, grandchildA2
			}
			return 'ctx';
		}
	});
	// childB and its child are still walked (only childA's children are skipped)
	assert.deepEqual(visited, ['root', 'childA', 'childB', 'grandchildB1']);
}

vows.describe('walkDOM').addBatch({
	'pre-order entry: calls enter on parent before children': function () {
		var root = buildTree().root;
		var visited = [];
		walkDOM(root, null, {
			enter: function (node) {
				visited.push(node.nodeName);
				// Descend into root so childA/childB are visited, but skip grandchildren
				if (node === root) return 'ctx';
				return null;
			}
		});
		// root entered first; childA and childB entered; grandchildren skipped
		assert.deepEqual(visited, ['root', 'childA', 'childB']);
	},
	'pre-order entry: visits all nodes in depth-first pre-order when enter returns a truthy context': function () {
		var root = buildTree().root;
		var visited = [];
		walkDOM(root, 'ctx', {
			enter: function (node) {
				visited.push(node.nodeName);
				return 'ctx';
			}
		});
		assert.deepEqual(visited, [
			'root',
			'childA',
			'grandchildA1',
			'grandchildA2',
			'childB',
			'grandchildB1'
		]);
	},
	'post-order exit: calls exit on a node after all its children have been exited': function () {
		var root = buildTree().root;
		var log = [];
		walkDOM(root, 'ctx', {
			enter: function (node) {
				log.push('enter:' + node.nodeName);
				return 'ctx';
			},
			exit: function (node) {
				log.push('exit:' + node.nodeName);
			}
		});
		// grandchildA1 exited before childA, childA exited before root
		var grandchildA1Exit = log.indexOf('exit:grandchildA1');
		var childAExit = log.indexOf('exit:childA');
		var rootExit = log.indexOf('exit:root');
		assert.ok(grandchildA1Exit !== -1, log.join(','));
		assert.ok(grandchildA1Exit < childAExit, log.join(','));
		assert.ok(childAExit < rootExit, log.join(','));
	},
	'post-order exit: passes the context returned by enter to exit': function () {
		var impl = new DOMImplementation();
		var doc = impl.createDocument(null, 'root');
		var root = doc.documentElement;
		root.appendChild(doc.createElement('child'));

		var exitContexts = [];
		walkDOM(root, 0, {
			enter: function (node, ctx) {
				return ctx + 1;
			},
			exit: function (node, ctx) {
				exitContexts.push({name: node.nodeName, ctx: ctx});
			}
		});
		// root enter gets ctx=0, returns 1; child enter gets ctx=1, returns 2
		// child exit gets ctx=2; root exit gets ctx=1
		assert.deepEqual(exitContexts, [
			{name: 'child', ctx: 2},
			{name: 'root', ctx: 1}
		]);
	},
	'context propagation: each child receives the return value of its parent enter': function () {
		var root = buildTree().root;
		var receivedCtx = {};
		walkDOM(root, 0, {
			enter: function (node, ctx) {
				receivedCtx[node.nodeName] = ctx;
				return ctx + 1;
			}
		});
		assert.strictEqual(receivedCtx['root'], 0);
		assert.strictEqual(receivedCtx['childA'], 1);
		assert.strictEqual(receivedCtx['grandchildA1'], 2);
		assert.strictEqual(receivedCtx['grandchildA2'], 2);
		assert.strictEqual(receivedCtx['childB'], 1);
		assert.strictEqual(receivedCtx['grandchildB1'], 2);
	},
	'STOP sentinel: returning walkDOM.STOP from enter aborts the entire traversal immediately': function () {
		var root = buildTree().root;
		var visited = [];
		var result = walkDOM(root, null, {
			enter: function (node) {
				visited.push(node.nodeName);
				if (node.nodeName === 'childA') {
					return walkDOM.STOP;
				}
				return 'ctx';
			},
			exit: function (node) {
				visited.push('exit:' + node.nodeName);
			}
		});
		// root and childA entered; traversal stops at childA — no children of childA,
		// no siblings (childB), no exit calls
		assert.deepEqual(visited, ['root', 'childA']);
		assert.strictEqual(result, walkDOM.STOP);
	},
	'skip children: returning null from enter skips children but continues with siblings': function () {
		skipChildrenOfChildA(null);
	},
	'skip children: returning undefined from enter skips children but continues with siblings': function () {
		skipChildrenOfChildA(undefined);
	},
	'enter modifies the child list before descent: walker visits a child added by enter': function () {
		var impl = new DOMImplementation();
		var doc = impl.createDocument(null, 'root');
		var root = doc.documentElement;
		root.appendChild(doc.createElement('original'));

		var visited = [];
		walkDOM(root, null, {
			enter: function (node) {
				visited.push(node.nodeName);
				if (node.nodeName === 'root') {
					// Add a new child before returning — walker should see it
					root.appendChild(doc.createElement('added'));
				}
				return 'ctx';
			}
		});
		assert.deepEqual(visited, ['root', 'original', 'added']);
	}
}).run();
