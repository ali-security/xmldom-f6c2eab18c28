var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;
var dom = require('xmldom/dom');
var DOMImplementation = dom.DOMImplementation;
var DOMException = dom.DOMException;

// CVE-2022-39353: insertBefore, appendChild and replaceChild did not check the
// pre-insertion validity of a node, so a Document could get more than one
// element child (root element), a doctype after the root element or a second
// doctype, which breaks the assumption that a document has a single root.
// https://github.com/xmldom/xmldom/security/advisories/GHSA-crh6-fp67-6883

// the codes are literals so the vows report the missing check (and not a
// TypeError) when DOMException is not exported
var HIERARCHY_REQUEST_ERR = 3;
var INVALID_CHARACTER_ERR = 5;
var NOT_FOUND_ERR = 8;

function assertThrowsDOMException(code, fn) {
	var thrown = null;
	try {
		fn();
	} catch (e) {
		thrown = e;
	}
	assert.ok(thrown, 'expected a DOMException with code ' + code + ' to be thrown');
	assert.strictEqual(thrown.code, code, 'unexpected exception: ' + thrown);
	return thrown;
}

function elementChildren(node) {
	var elements = [];
	for (var child = node.firstChild; child; child = child.nextSibling) {
		if (child.nodeType === 1) {
			elements.push(child);
		}
	}
	return elements;
}

vows.describe('Document pre-insertion validity').addBatch({
	'DOMException is exported with its codes': function () {
		assert.equal(typeof DOMException, 'function');
		assert.strictEqual(DOMException.HIERARCHY_REQUEST_ERR, HIERARCHY_REQUEST_ERR);
		assert.strictEqual(DOMException.NOT_FOUND_ERR, NOT_FOUND_ERR);
	},
	'createDocument sets ownerDocument to the document itself': function () {
		var impl = new DOMImplementation();
		var doc = impl.createDocument(null, '');
		assert.strictEqual(doc.ownerDocument, doc);
		assert.strictEqual(doc.childNodes.length, 0);
		assert.strictEqual(doc.documentElement, null);
		var doctype = impl.createDocumentType('html');
		var docWithDoctype = impl.createDocument(null, '', doctype);
		assert.strictEqual(docWithDoctype.ownerDocument, docWithDoctype);
	}
}).addBatch({
	'insertBefore inserts the first element and sets documentElement': function () {
		var doc = new DOMImplementation().createDocument(null, '');
		assert.strictEqual(doc.childNodes.length, 0);
		assert.strictEqual(doc.documentElement, null);
		var root = doc.createElement('root');
		doc.insertBefore(root);
		assert.strictEqual(doc.documentElement, root);
		assert.strictEqual(doc.childNodes.length, 1);
		assert.strictEqual(doc.childNodes.item(0), root);
	},
	'insertBefore prevents inserting a second element': function () {
		var doc = new DOMImplementation().createDocument(null, '');
		var root = doc.createElement('root');
		var second = doc.createElement('second');
		doc.insertBefore(root);
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.insertBefore(second);
		});
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.insertBefore(second, root);
		});
		assert.strictEqual(doc.documentElement, root);
		assert.strictEqual(doc.childNodes.length, 1);
		assert.strictEqual(second.parentNode, null);
		assert.equal(doc.toString(), '<root/>');
	},
	'appendChild prevents appending a second element': function () {
		var doc = new DOMImplementation().createDocument(null, 'root');
		var second = doc.createElement('second');
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.appendChild(second);
		});
		assert.equal(doc.documentElement.tagName, 'root');
		assert.strictEqual(doc.childNodes.length, 1);
		assert.strictEqual(elementChildren(doc).length, 1);
		assert.equal(doc.toString(), '<root/>');
	},
	'Node.prototype.insertBefore applied to a document prevents a second element': function () {
		var doc = new DOMImplementation().createDocument(null, 'root');
		// Element does not override insertBefore, so this is Node.prototype.insertBefore
		var nodeInsertBefore = doc.documentElement.insertBefore;
		var second = doc.createElement('second');
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			nodeInsertBefore.call(doc, second, null);
		});
		assert.strictEqual(elementChildren(doc).length, 1);
	},
	'insertBefore prevents inserting an element before a doctype': function () {
		var impl = new DOMImplementation();
		var doctype = impl.createDocumentType('DT');
		var doc = impl.createDocument(null, '', doctype);
		assert.strictEqual(doc.childNodes.length, 1);
		var root = doc.createElement('root');
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.insertBefore(root, doctype);
		});
		assert.strictEqual(doc.documentElement, null);
		assert.strictEqual(doc.childNodes.length, 1);
		assert.strictEqual(root.parentNode, null);
	},
	'insertBefore prevents inserting a second doctype': function () {
		var impl = new DOMImplementation();
		var doctype = impl.createDocumentType('DT');
		var doctype2 = impl.createDocumentType('DT2');
		var doc = impl.createDocument(null, '', doctype);
		assert.strictEqual(doc.childNodes.length, 1);
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.insertBefore(doctype2);
		});
		assert.strictEqual(doc.childNodes.length, 1);
	},
	'insertBefore prevents inserting a doctype after an element': function () {
		var impl = new DOMImplementation();
		var doc = impl.createDocument(null, '');
		var root = doc.createElement('root');
		doc.insertBefore(root);
		var doctype = impl.createDocumentType('DT');
		assert.strictEqual(doc.childNodes.length, 1);
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.insertBefore(doctype);
		});
		var comment = doc.createComment('after');
		doc.appendChild(comment);
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.insertBefore(doctype, comment);
		});
		assert.strictEqual(doc.childNodes.length, 2);
		assert.strictEqual(doctype.parentNode, null);
	},
	'insertBefore prevents inserting before a child which is not a child of parent': function () {
		var doc = new DOMImplementation().createDocument(null, '');
		var root = doc.createElement('root');
		var withoutParent = doc.createElement('second');
		assertThrowsDOMException(NOT_FOUND_ERR, function () {
			doc.insertBefore(root, withoutParent);
		});
		assert.strictEqual(doc.documentElement, null);
		assert.strictEqual(doc.childNodes.length, 0);
		assert.strictEqual(root.parentNode, null);
	},
	'insertBefore prevents inserting before a child that was removed': function () {
		var doc = new DOMImplementation().createDocument(null, 'root');
		var comment = doc.createComment('removed');
		doc.insertBefore(comment, doc.documentElement);
		doc.removeChild(comment);
		assertThrowsDOMException(NOT_FOUND_ERR, function () {
			doc.insertBefore(doc.createComment('new'), comment);
		});
		assert.strictEqual(doc.childNodes.length, 1);
		assert.equal(doc.toString(), '<root/>');
	},
	'insertBefore prevents inserting a fragment that adds a second element': function () {
		var doc = new DOMImplementation().createDocument(null, 'root');
		var fragment = doc.createDocumentFragment();
		fragment.appendChild(doc.createElement('second'));
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.insertBefore(fragment, null);
		});
		assert.strictEqual(elementChildren(doc).length, 1);
		assert.equal(doc.documentElement.tagName, 'root');
	},
	'a fragment with two elements can not be inserted into an empty document': function () {
		var doc = new DOMImplementation().createDocument(null, '');
		var fragment = doc.createDocumentFragment();
		fragment.appendChild(doc.createElement('first'));
		fragment.appendChild(doc.createElement('second'));
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.appendChild(fragment);
		});
		assert.strictEqual(elementChildren(doc).length, 1);
	},
	'insertBefore still allows a well-formed document': function () {
		var impl = new DOMImplementation();
		var doc = impl.createDocument(null, '');
		var root = doc.createElement('root');
		doc.appendChild(doc.createProcessingInstruction('xml-stylesheet', 'href="a.xsl"'));
		doc.appendChild(doc.createComment('before'));
		doc.appendChild(root);
		doc.appendChild(doc.createComment('after'));
		var doctype = impl.createDocumentType('root');
		doc.insertBefore(doctype, root);
		assert.strictEqual(doc.documentElement, root);
		assert.strictEqual(doc.childNodes.length, 5);
		assert.strictEqual(root.previousSibling, doctype);
		assert.equal(doc.toString(), '<?xml-stylesheet href="a.xsl"?><!--before--><!DOCTYPE root><root/><!--after-->');
	},
	'a doctype can be inserted before a comment while there is no element': function () {
		var impl = new DOMImplementation();
		var doc = impl.createDocument(null, '');
		var comment = doc.createComment('c');
		doc.appendChild(comment);
		var doctype = impl.createDocumentType('root');
		doc.insertBefore(doctype, comment);
		assert.strictEqual(doc.firstChild, doctype);
		assert.strictEqual(doc.childNodes.length, 2);
	},
	'a new element can be added after the element was removed': function () {
		var doc = new DOMImplementation().createDocument(null, 'root');
		var root = doc.documentElement;
		doc.removeChild(root);
		assert.strictEqual(doc.documentElement, null);
		assert.strictEqual(doc.childNodes.length, 0);
		var other = doc.createElement('other');
		doc.appendChild(other);
		assert.strictEqual(doc.documentElement, other);
		assert.strictEqual(doc.childNodes.length, 1);
		assert.equal(doc.toString(), '<other/>');
	},
	'elements and fragments can still hold CDATA sections': function () {
		var doc = new DOMParser().parseFromString('<root><a/></root>', 'text/xml');
		var root = doc.documentElement;
		root.insertBefore(doc.createCDATASection('x'), root.firstChild);
		var fragment = doc.createDocumentFragment();
		fragment.appendChild(doc.createCDATASection('y'));
		root.appendChild(fragment);
		assert.equal(doc.toString(), '<root><![CDATA[x]]><a/><![CDATA[y]]></root>');
	}
}).addBatch({
	'replaceChild removes the only element and adds the new one': function () {
		var doc = new DOMImplementation().createDocument('', 'xml');
		var initialFirstChild = doc.firstChild;
		var replacement = doc.createElement('replaced');
		doc.replaceChild(replacement, doc.firstChild);
		assert.strictEqual(doc.childNodes.length, 1);
		assert.strictEqual(initialFirstChild.parentNode, null);
		assert.strictEqual(doc.documentElement, replacement);
		assert.equal(doc.toString(), '<replaced/>');
	},
	'replaceChild prevents replacing another node with a second element': function () {
		var doc = new DOMImplementation().createDocument(null, 'root');
		var comment = doc.createComment('c');
		doc.appendChild(comment);
		var second = doc.createElement('second');
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.replaceChild(second, comment);
		});
		assert.strictEqual(elementChildren(doc).length, 1);
		assert.strictEqual(comment.parentNode, doc);
		assert.strictEqual(second.parentNode, null);
		assert.equal(doc.toString(), '<root/><!--c-->');
	},
	'Node.prototype.replaceChild applied to a document prevents a second element': function () {
		var doc = new DOMImplementation().createDocument(null, 'root');
		var comment = doc.createComment('c');
		doc.appendChild(comment);
		// Element does not override replaceChild, so this is Node.prototype.replaceChild
		var nodeReplaceChild = doc.documentElement.replaceChild;
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			nodeReplaceChild.call(doc, doc.createElement('second'), comment);
		});
		assert.strictEqual(elementChildren(doc).length, 1);
	},
	'replaceChild prevents replacing with a fragment holding two elements': function () {
		var doc = new DOMImplementation().createDocument(null, 'root');
		var fragment = doc.createDocumentFragment();
		fragment.appendChild(doc.createElement('first'));
		fragment.appendChild(doc.createElement('second'));
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.replaceChild(fragment, doc.documentElement);
		});
		assert.strictEqual(elementChildren(doc).length, 1);
		assert.equal(doc.toString(), '<root/>');
	},
	'replaceChild prevents a second doctype and a doctype after the element': function () {
		var impl = new DOMImplementation();
		var doc = impl.createDocument(null, 'root', impl.createDocumentType('root'));
		var comment = doc.createComment('c');
		doc.appendChild(comment);
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.replaceChild(impl.createDocumentType('other'), comment);
		});
		doc.removeChild(doc.firstChild);
		assertThrowsDOMException(HIERARCHY_REQUEST_ERR, function () {
			doc.replaceChild(impl.createDocumentType('other'), comment);
		});
		assert.equal(doc.toString(), '<root/><!--c-->');
	}
}).addBatch({
	'removeChild removes all connections to the node': function () {
		var doc = new DOMImplementation().createDocument('', 'xml');
		doc.insertBefore(doc.createComment('just a comment'), doc.firstChild);
		assert.strictEqual(doc.childNodes.length, 2);
		var initialElement = doc.firstChild;
		doc.removeChild(initialElement);
		assert.strictEqual(initialElement.parentNode, null);
		assert.strictEqual(initialElement.nextSibling, null);
		assert.strictEqual(initialElement.previousSibling, null);
		assert.strictEqual(doc.childNodes.length, 1);
	}
}).addBatch({
	// CVE-2026-83610: createEntityReference accepted any name, and the serializer emits the
	// name as is between "&" and ";", so a crafted name could inject markup.
	'createEntityReference creates an EntityReference with a valid name': function () {
		var doc = new DOMImplementation().createDocument(null, '');
		var eref = doc.createEntityReference('amp');
		assert.strictEqual(eref.nodeType, 5);
		assert.strictEqual(eref.nodeType, doc.ENTITY_REFERENCE_NODE);
		assert.strictEqual(eref.nodeName, 'amp');
		assert.strictEqual(eref.ownerDocument, doc);
		assert.strictEqual(doc.createEntityReference('_x-1.y').nodeName, '_x-1.y');
	},
	'createEntityReference throws for a name that is not a valid XML Name': function () {
		var doc = new DOMImplementation().createDocument(null, '');
		assertThrowsDOMException(INVALID_CHARACTER_ERR, function () {
			doc.createEntityReference('123');
		});
	},
	'createEntityReference throws for a name with a valid prefix but ill-formed remainder': function () {
		var doc = new DOMImplementation().createDocument(null, '');
		assertThrowsDOMException(INVALID_CHARACTER_ERR, function () {
			doc.createEntityReference('safe; <injected/> &x');
		});
	},
	'createEntityReference throws for markup injection payloads': function () {
		var doc = new DOMImplementation().createDocument(null, 'root');
		var names = ['', 'a b', 'amp;<injected/>&amp', 'lt;--><script>alert(1)</script><!--', 'a' + String.fromCharCode(0x0A)];
		for (var i = 0; i < names.length; i++) {
			var name = names[i];
			assertThrowsDOMException(INVALID_CHARACTER_ERR, function () {
				doc.createEntityReference(name);
			});
		}
	}
}).run();
