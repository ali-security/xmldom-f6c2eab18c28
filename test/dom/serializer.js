var wows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;
var XMLSerializer = require('xmldom').XMLSerializer;
var DOMImplementation = require('xmldom/dom').DOMImplementation;

// CVE-2026-34601: CDATASection data containing "]]>" was serialized verbatim,
// which terminates the CDATA section early so the rest of the data became
// live markup in the serialized XML.
// https://github.com/xmldom/xmldom/security/advisories/GHSA-wh4c-j3r5-mjhp

// the code is a literal so the vows report the missing check (and not a
// TypeError) when DOMException is not exported
var INVALID_CHARACTER_ERR = 5;
var INVALID_STATE_ERR = 11;

// GHSA-j759-j44w-7fr8 proof of concept: closes the comment and injects an element
var COMMENT_PAYLOAD = '--><injected attr="1"/><!--';

// GHSA-27p8-2357-5qqv proof of concept: closes the DOCTYPE through its name and injects a script
var DOCTYPE_NAME_PAYLOAD = 'html><script xmlns="http://www.w3.org/1999/xhtml">alert(1)</script';

// GHSA-x6wf-f3px-wcqx proof of concept: closes the processing instruction and injects an element
var PI_PAYLOAD = '?><injected/><?q ';

// GHSA-4w3w-2rp5-g8jm proof of concept: the attribute name closes the intended attribute
// and injects an event handler
var ATTRIBUTE_NAME_PAYLOAD = 'class="safe" onclick';

// GHSA-w2rr-34g9-rvrj proof of concept: the element name injects attributes into the start tag
var ELEMENT_NAME_PAYLOAD = 'img src=x onerror="alert(1)"';

// CVE-2026-83610 proof of concept: the entity reference name closes the reference and
// injects an element
var ENTITY_REFERENCE_NAME_PAYLOAD = 'amp;<injected/>&amp';

function createRootDocument() {
  return new DOMImplementation().createDocument(null, 'root', null);
}

// Returns a document with a root element and a DocumentType created from the arguments as is.
function createDoctypeDocument(name, publicId, systemId) {
  var impl = new DOMImplementation();
  return impl.createDocument(null, 'root', impl.createDocumentType(name, publicId, systemId));
}

// Serializing `doc` with requireWellFormed throws, so the DocumentType payload never reaches the output.
function assertDoctypeRejected(doc) {
  assertThrowsDOMException(INVALID_STATE_ERR, function() {
    new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
  });
}

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

// Serializes, then re-parses, and returns true if an <injected> element appears in the tree.
function isInjected(root) {
  var xml = new XMLSerializer().serializeToString(root);
  var reparsed = new DOMParser().parseFromString(xml, 'text/xml');
  return reparsed.getElementsByTagName('injected').length > 0;
}

wows.describe('XML Serializer').addBatch({
  'text node containing "]]>"': function() {
    var doc = new DOMParser().parseFromString('<test/>', 'text/xml');
    doc.documentElement.appendChild(doc.createTextNode('hello ]]> there'));
    console.assert(doc.documentElement.firstChild.toString() == 'hello ]]> there',doc.documentElement.firstChild.toString());
  },
  '<script> element with no children': function() {
    var doc = new DOMParser({xmlns:{xmlns:'http://www.w3.org/1999/xhtml'}}).parseFromString('<html2><script></script></html2>', 'text/html');
    //console.log(doc.documentElement.firstChild.toString(true))
    console.assert(doc.documentElement.firstChild.toString() == '<script></script>');
  },
}).addBatch({
  // CVE-2026-34601: XMLSerializer CDATASection serialization
  'serializes a safe CDATASection unchanged': function () {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createCDATASection('safe data'));
    assert.equal(new XMLSerializer().serializeToString(doc.documentElement),
      '<root><![CDATA[safe data]]></root>');
  },
  'splits a CDATASection whose data contains "]]>"': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assert.equal(new XMLSerializer().serializeToString(doc.documentElement),
      '<root><![CDATA[foo]]]]><![CDATA[>bar]]></root>');
  },
  'splits multiple "]]>" occurrences': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'a]]>b]]>c';
    doc.documentElement.appendChild(cdata);
    assert.equal(new XMLSerializer().serializeToString(doc.documentElement),
      '<root><![CDATA[a]]]]><![CDATA[>b]]]]><![CDATA[>c]]></root>');
  },
  'split output round-trips through DOMParser to equivalent content': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    var serialized = new XMLSerializer().serializeToString(doc.documentElement);
    var reparsed = new DOMParser().parseFromString(serialized, 'text/xml');
    assert.equal(reparsed.documentElement.textContent, 'foo]]>bar');
  },
  'mutation vectors': {
    'appendData introduces "]]>" safely': function () {
      var doc = createRootDocument();
      var cdata = doc.createCDATASection('safe');
      doc.documentElement.appendChild(cdata);
      cdata.appendData(']]><injected/>');
      assert.strictEqual(isInjected(doc.documentElement), false);
    },
    'insertData introduces "]]>" safely': function () {
      var doc = createRootDocument();
      var cdata = doc.createCDATASection('safe');
      doc.documentElement.appendChild(cdata);
      cdata.insertData(2, ']]><injected/>');
      assert.strictEqual(isInjected(doc.documentElement), false);
    },
    'replaceData introduces "]]>" safely': function () {
      var doc = createRootDocument();
      var cdata = doc.createCDATASection('safe data');
      doc.documentElement.appendChild(cdata);
      cdata.replaceData(4, 5, ']]><injected/>');
      assert.strictEqual(isInjected(doc.documentElement), false);
    },
    '.data assignment introduces "]]>" safely': function () {
      var doc = createRootDocument();
      var cdata = doc.createCDATASection('safe');
      doc.documentElement.appendChild(cdata);
      cdata.data = 'evil]]><injected/>';
      assert.strictEqual(isInjected(doc.documentElement), false);
    },
    '.textContent assignment introduces "]]>" safely': function () {
      var doc = createRootDocument();
      var cdata = doc.createCDATASection('safe');
      doc.documentElement.appendChild(cdata);
      cdata.textContent = 'evil]]><injected/>';
      assert.strictEqual(isInjected(doc.documentElement), false);
    },
    'Node.toString and NodeList.toString split "]]>" too': function () {
      var doc = createRootDocument();
      var cdata = doc.createCDATASection('safe');
      doc.documentElement.appendChild(cdata);
      cdata.data = 'evil]]><injected/>';
      var expected = '<root><![CDATA[evil]]]]><![CDATA[><injected/>]]></root>';
      assert.equal(doc.toString(), expected);
      assert.equal(doc.documentElement.toString(), expected);
      assert.equal(doc.childNodes.toString(), expected);
    }
  }
}).addBatch({
  // CVE-2026-34601: XMLSerializer serializeToString requireWellFormed option
  'CDATA with "]]>" still splits when no options are passed (regression)': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assert.equal(new XMLSerializer().serializeToString(doc.documentElement),
      '<root><![CDATA[foo]]]]><![CDATA[>bar]]></root>');
  },
  'CDATA with "]]>" still splits when options is null (regression)': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assert.equal(new XMLSerializer().serializeToString(doc.documentElement, false, null, null),
      '<root><![CDATA[foo]]]]><![CDATA[>bar]]></root>');
  },
  'CDATA with "]]>" still splits when requireWellFormed is false': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assert.equal(new XMLSerializer().serializeToString(doc, false, null, {requireWellFormed: false}),
      '<root><![CDATA[foo]]]]><![CDATA[>bar]]></root>');
  },
  'requireWellFormed: true on a safe CDATA does not throw': function () {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createCDATASection('safe data'));
    assert.equal(new XMLSerializer().serializeToString(doc, false, null, {requireWellFormed: true}),
      '<root><![CDATA[safe data]]></root>');
  },
  'requireWellFormed: true on CDATA with "]]>" throws': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assertThrowsDOMException(INVALID_STATE_ERR, function () {
      new XMLSerializer().serializeToString(doc, false, null, {requireWellFormed: true});
    });
  },
  'node.toString with requireWellFormed: true on CDATA with "]]>" throws': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assertThrowsDOMException(INVALID_STATE_ERR, function () {
      doc.toString(false, null, {requireWellFormed: true});
    });
  },
  'nodeList.toString with requireWellFormed: true on CDATA with "]]>" throws': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assertThrowsDOMException(INVALID_STATE_ERR, function () {
      doc.childNodes.toString(false, null, {requireWellFormed: true});
    });
  }
}).addBatch({
  // CVE-2026-41672: Comment data was serialized as is, so "-->" in the data closed the
  // comment early and the rest of the data became live markup.
  // https://github.com/xmldom/xmldom/security/advisories/GHSA-j759-j44w-7fr8
  'default: comment with "-->" in data emits verbatim - no throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello-->world'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><!--hello-->world--></root>');
  },
  'default: comment with "--" in data emits verbatim - no throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello--world'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><!--hello--world--></root>');
  },
  'requireWellFormed: true on comment with invalid XML Char (\\x00) throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello' + String.fromCharCode(0) + 'world'));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
    });
  },
  'requireWellFormed: true on comment with "-->" throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello-->world'));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
    });
  },
  'requireWellFormed: true on comment with "--" (no "-->") throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello--world'));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
    });
  },
  'requireWellFormed: true on comment whose data ends with "-" throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello-'));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
    });
  },
  'requireWellFormed: true on comment with clean data does not throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('clean comment'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<root><!--clean comment--></root>');
  },
  'mutation vector: appendData("-->") then requireWellFormed: true throws InvalidStateError': function() {
    var doc = createRootDocument();
    var comment = doc.createComment('clean');
    doc.documentElement.appendChild(comment);
    comment.appendData('-->');
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
    });
  }
}).addBatch({
  // the advisory's proof of concept, and every way it lists to get the payload into a comment
  'advisory PoC: injected element survives a default round-trip': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment(COMMENT_PAYLOAD));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><!----><injected attr="1"/><!----></root>');
    assert.strictEqual(isInjected(doc.documentElement), true);
  },
  'advisory PoC: createComment payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment(COMMENT_PAYLOAD));
    assertCommentRejected(doc);
  },
  'insertData payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var comment = doc.createComment('safe');
    doc.documentElement.appendChild(comment);
    comment.insertData(2, COMMENT_PAYLOAD);
    assertCommentRejected(doc);
  },
  'replaceData payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var comment = doc.createComment('safe data');
    doc.documentElement.appendChild(comment);
    comment.replaceData(4, 5, COMMENT_PAYLOAD);
    assertCommentRejected(doc);
  },
  '.data assignment payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var comment = doc.createComment('safe');
    doc.documentElement.appendChild(comment);
    comment.data = COMMENT_PAYLOAD;
    assertCommentRejected(doc);
  },
  '.textContent assignment payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var comment = doc.createComment('safe');
    doc.documentElement.appendChild(comment);
    comment.textContent = COMMENT_PAYLOAD;
    assertCommentRejected(doc);
  },
  'payload in a parsed document comment throws with requireWellFormed: true': function() {
    var doc = new DOMParser().parseFromString('<root><!-- safe --></root>', 'text/xml');
    doc.documentElement.firstChild.data = COMMENT_PAYLOAD;
    assertCommentRejected(doc);
  },
  'payload in a nested comment throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var child = doc.createElement('child');
    doc.documentElement.appendChild(child);
    child.appendChild(doc.createComment(COMMENT_PAYLOAD));
    assertCommentRejected(doc);
  },
  'payload in a DocumentFragment comment throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var fragment = doc.createDocumentFragment();
    fragment.appendChild(doc.createComment(COMMENT_PAYLOAD));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(fragment, false, null, { requireWellFormed: true });
    });
  },
  'node.toString with requireWellFormed: true on a comment payload throws': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment(COMMENT_PAYLOAD));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.toString(false, null, { requireWellFormed: true });
    });
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.documentElement.firstChild.toString(false, null, { requireWellFormed: true });
    });
  },
  'NodeList.toString with requireWellFormed: true on a comment payload throws': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment(COMMENT_PAYLOAD));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.documentElement.childNodes.toString(false, null, { requireWellFormed: true });
    });
  }
}).addBatch({
  'requireWellFormed: true on comment with an unpaired surrogate throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('a' + String.fromCharCode(0xD800) + 'b'));
    assertCommentRejected(doc);
    doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('a' + String.fromCharCode(0xDC00)));
    assertCommentRejected(doc);
  },
  'requireWellFormed: true on comment with U+FFFE throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('a' + String.fromCharCode(0xFFFE)));
    assertCommentRejected(doc);
  },
  'requireWellFormed: true on comment with a surrogate pair (U+1F600) does not throw': function() {
    var doc = createRootDocument();
    var data = 'smile ' + String.fromCharCode(0xD83D, 0xDE00) + ' tab\tnewline\n';
    doc.documentElement.appendChild(doc.createComment(data));
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<root><!--' + data + '--></root>');
  },
  'requireWellFormed: true on a parsed well-formed comment round-trips': function() {
    var xml = '<root><!-- a - b --><child/></root>';
    var doc = new DOMParser().parseFromString(xml, 'text/xml');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }), xml);
  },
  'requireWellFormed: false keeps the verbatim comment output': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello-->world'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: false }),
      '<root><!--hello-->world--></root>');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, null),
      '<root><!--hello-->world--></root>');
  }
}).addBatch({
  // CVE-2026-41674: the DocumentType publicId, systemId and internalSubset were serialized
  // without any check, even with requireWellFormed: true, so a crafted value could close the
  // DOCTYPE declaration early and inject markup (e.g. an entity declaration).
  // In this version publicId and systemId hold the unquoted identifier and the serializer
  // quotes it (_quoteDoctypeId), so the checks apply to the unquoted content.
  // https://github.com/xmldom/xmldom/security/advisories/GHSA-f6ww-3ggp-fr8h
  'default: DocumentType with invalid publicId serializes as a literal - no throw': function() {
    var doc = createDoctypeDocument('name', 'invalid<char', '');
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<!DOCTYPE name PUBLIC "invalid<char"><root/>');
  },
  'requireWellFormed: true on DocumentType with invalid publicId throws InvalidStateError': function() {
    assertDoctypeRejected(createDoctypeDocument('name', 'invalid<char', ''));
  },
  'requireWellFormed: true on DocumentType with a systemId containing both quotes throws InvalidStateError': function() {
    assertDoctypeRejected(createDoctypeDocument('name', '', 'a"b\'c'));
  },
  'requireWellFormed: true on DocumentType with "]>" in internalSubset throws InvalidStateError': function() {
    var doc = createDoctypeDocument('name', '', '');
    doc.doctype.internalSubset = ']><injected/>';
    assertDoctypeRejected(doc);
  },
  'requireWellFormed: true on DocumentType with valid fields does not throw': function() {
    var doc = createDoctypeDocument('html', '-//W3C//DTD HTML 4.01//EN', 'http://www.w3.org/TR/html4/strict.dtd');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd"><root/>');
  },
  'direct property write: setting invalid publicId then requireWellFormed: true throws InvalidStateError': function() {
    var doc = createDoctypeDocument('name', '-//W3C//DTD//EN', '');
    doc.doctype.publicId = 'invalid<char';
    assertDoctypeRejected(doc);
  }
}).addBatch({
  // the injection vectors: each payload is rejected with requireWellFormed: true
  'systemId with both quotes injecting an entity declaration (XXE) throws with requireWellFormed: true': function() {
    var doc = createDoctypeDocument('root', '', 'x.dtd\' [<!ENTITY xxe SYSTEM "file:///etc/passwd">]');
    assertDoctypeRejected(doc);
  },
  'publicId closing the declaration early throws with requireWellFormed: true': function() {
    var doc = createDoctypeDocument('root', '-//X//EN"><injected/', '');
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<!DOCTYPE root PUBLIC \'-//X//EN"><injected/\'><root/>');
    assertDoctypeRejected(doc);
  },
  'systemId after a publicId closing the declaration early throws with requireWellFormed: true': function() {
    var doc = createDoctypeDocument('root', '-//X//EN', 'x.dtd\'"><injected/');
    assertDoctypeRejected(doc);
  },
  'internalSubset closing the declaration early throws with requireWellFormed: true': function() {
    var doc = createDoctypeDocument('root', '', '');
    doc.doctype.internalSubset = '<!ENTITY a "b">]><injected/><!--';
    assert.strictEqual(new XMLSerializer().serializeToString(doc),
      '<!DOCTYPE root [<!ENTITY a "b">]><injected/><!--]><root/>');
    assertDoctypeRejected(doc);
  },
  'a valid value followed by a line terminator and a payload throws (GHSA-vr34-hp96-76pp)': function() {
    var terminators = [String.fromCharCode(0x0A), String.fromCharCode(0x0D), String.fromCharCode(0x2028), String.fromCharCode(0x2029)];
    for (var i = 0; i < terminators.length; i++) {
      var lt = terminators[i];
      assertDoctypeRejected(createDoctypeDocument('html', 'valid pubid' + lt + '"><!ENTITY xxe SYSTEM "file:///etc/passwd">', ''));
      assertDoctypeRejected(createDoctypeDocument('html', '', 'valid.dtd' + lt + '\'[<!ENTITY xxe SYSTEM "file:///etc/passwd">]'));
      assertDoctypeRejected(createDoctypeDocument('html', '-//X//EN', 'valid.dtd' + lt + '\'"><injected/'));
    }
  },
  'a publicId with a double quote inside throws with requireWellFormed: true': function() {
    // a double quote is not a PubidChar
    assertDoctypeRejected(createDoctypeDocument('root', 'a"b', ''));
    assertDoctypeRejected(createDoctypeDocument('root', 'it\'s"', ''));
  },
  'serializing the DocumentType node itself with requireWellFormed: true throws': function() {
    var doc = createDoctypeDocument('root', '-//X//EN"><injected/', '');
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(doc.doctype, false, null, { requireWellFormed: true });
    });
  },
  'node.toString and NodeList.toString with requireWellFormed: true on a DocumentType payload throw': function() {
    var doc = createDoctypeDocument('root', '', 'x.dtd\' [<!ENTITY xxe SYSTEM "file:///etc/passwd">]');
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.toString(false, null, { requireWellFormed: true });
    });
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.doctype.toString(false, null, { requireWellFormed: true });
    });
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.childNodes.toString(false, null, { requireWellFormed: true });
    });
  },
  'requireWellFormed: true accepts well-formed values': function() {
    // a publicId may contain a single quote and line feeds (serialized in double quotes),
    // a systemId may contain one kind of quote (serialized in the other one)
    var doc = createDoctypeDocument('root', '-//X//DTD a\'b' + String.fromCharCode(0x0A) + 'c//EN', 'sys"tem.dtd');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<!DOCTYPE root PUBLIC "-//X//DTD a\'b' + String.fromCharCode(0x0A) + 'c//EN" \'sys"tem.dtd\'><root/>');
    doc = createDoctypeDocument('root', '', 'x.dtd" [<!ENTITY xxe SYSTEM "file:///etc/passwd">]');
    // a systemId with only double quotes stays one SystemLiteral, nothing is injected
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<!DOCTYPE root SYSTEM \'x.dtd" [<!ENTITY xxe SYSTEM "file:///etc/passwd">]\'><root/>');
    doc = createDoctypeDocument('root', '', '');
    doc.doctype.internalSubset = '<!ENTITY a "b">';
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<!DOCTYPE root [<!ENTITY a "b">]><root/>');
  },
  'requireWellFormed: false keeps the default DocumentType output': function() {
    var doc = createDoctypeDocument('root', '-//X//EN"><injected/', '');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: false }),
      '<!DOCTYPE root PUBLIC \'-//X//EN"><injected/\'><root/>');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, null),
      '<!DOCTYPE root PUBLIC \'-//X//EN"><injected/\'><root/>');
  }
}).addBatch({
  // The DocumentType name was not checked by the CVE-2026-41674 fix either: a ">" in the name
  // closes the declaration early, and the name is a plain writable property.
  // https://github.com/xmldom/xmldom/security/advisories/GHSA-27p8-2357-5qqv
  'default: DocumentType with invalid name serializes verbatim - no throw': function() {
    var doc = createDoctypeDocument('html', '', '');
    doc.doctype.name = DOCTYPE_NAME_PAYLOAD;
    var out = new XMLSerializer().serializeToString(doc);
    assert.ok(out.indexOf('<!DOCTYPE html><script') === 0, out);
  },
  'requireWellFormed: true on DocumentType with ">" in name throws': function() {
    var doc = createDoctypeDocument('html', '', '');
    doc.doctype.name = DOCTYPE_NAME_PAYLOAD;
    assertDoctypeRejected(doc);
  },
  'requireWellFormed: true on DocumentType with whitespace in name throws': function() {
    var doc = createDoctypeDocument('html', '', '');
    doc.doctype.name = 'ht ml';
    assertDoctypeRejected(doc);
  },
  'requireWellFormed: true on a name passed to createDocumentType throws': function() {
    assertDoctypeRejected(createDoctypeDocument(DOCTYPE_NAME_PAYLOAD, '', ''));
    assertDoctypeRejected(createDoctypeDocument('html><!--INJECTED--', '', ''));
    assertDoctypeRejected(createDoctypeDocument('html [<!ENTITY xxe SYSTEM "file:///etc/passwd">]', '', ''));
    assertDoctypeRejected(createDoctypeDocument('', '', ''));
    assertDoctypeRejected(createDoctypeDocument('html' + String.fromCharCode(0x0A), '', ''));
  },
  'requireWellFormed: true accepts valid XML names': function() {
    var names = ['html', 'svg:svg', '_x-1.y', 'r\u00E9sum\u00E9'];
    for (var i = 0; i < names.length; i++) {
      var doc = createDoctypeDocument(names[i], '', '');
      assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
        '<!DOCTYPE ' + names[i] + '><root/>');
    }
  }
}).addBatch({
  // DOCTYPEs produced by the parser keep serializing with requireWellFormed: true
  // (the serializer quotes the unquoted publicId/systemId, preferring double quotes)
  'parsed DOCTYPEs serialize with requireWellFormed: true': function() {
    var cases = [
      ['<!DOCTYPE x PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><x/>',
        '<!DOCTYPE x PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><x/>'],
      ['<!DOCTYPE x PUBLIC "-//W3C//DTD HTML 4.01//EN"><x/>', '<!DOCTYPE x PUBLIC "-//W3C//DTD HTML 4.01//EN"><x/>'],
      ['<!DOCTYPE x PUBLIC \'-//W3C//DTD HTML 4.01//EN\' \'strict.dtd\'><x/>', '<!DOCTYPE x PUBLIC "-//W3C//DTD HTML 4.01//EN" "strict.dtd"><x/>'],
      ['<!DOCTYPE x SYSTEM "x.dtd"><x/>', '<!DOCTYPE x SYSTEM "x.dtd"><x/>'],
      ['<!DOCTYPE x SYSTEM \'x.dtd\'><x/>', '<!DOCTYPE x SYSTEM "x.dtd"><x/>'],
      ['<!DOCTYPE x SYSTEM \'"\'><x/>', '<!DOCTYPE x SYSTEM \'"\'><x/>']
    ];
    for (var i = 0; i < cases.length; i++) {
      var doc = new DOMParser().parseFromString(cases[i][0], 'text/xml');
      assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }), cases[i][1]);
    }
  },
  'a parsed DOCTYPE with an invalid PubidLiteral throws with requireWellFormed: true': function() {
    var doc = new DOMParser().parseFromString('<!DOCTYPE x PUBLIC \'"\'><x/>', 'text/xml');
    assert.strictEqual(doc.firstChild.publicId, '"');
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<!DOCTYPE x PUBLIC \'"\'><x/>');
    assertDoctypeRejected(doc);
  }
}).addBatch({
  // CVE-2026-41675: ProcessingInstruction data was serialized as is, so "?>" in the data closed
  // the processing instruction early and the rest of the data became live markup.
  // https://github.com/xmldom/xmldom/security/advisories/GHSA-x6wf-f3px-wcqx
  'default: PI with ":" in target emits verbatim - no throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('ns:target', 'data'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><?ns:target data?></root>');
  },
  'default: PI with target "xml" emits verbatim - no throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('xml', 'version="1.0"'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><?xml version="1.0"?></root>');
  },
  'default: PI with invalid XML Char in data emits verbatim - no throw': function() {
    var doc = createRootDocument();
    var data = 'data' + String.fromCharCode(0) + 'here';
    doc.documentElement.appendChild(doc.createProcessingInstruction('foo', data));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><?foo ' + data + '?></root>');
  },
  'default: PI with "?>" in data emits verbatim - no throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('foo', 'inject?>evil'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><?foo inject?>evil?></root>');
  },
  'requireWellFormed: true on PI with ":" in target throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('ns:target', 'data'));
    assertPIRejected(doc);
  },
  'requireWellFormed: true on PI with target "xml" throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('xml', 'version="1.0"'));
    assertPIRejected(doc);
  },
  'requireWellFormed: true on PI with target "XML" (uppercase) throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('XML', 'data'));
    assertPIRejected(doc);
  },
  'requireWellFormed: true on PI with target "Xml" (mixed case) throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('Xml', 'data'));
    assertPIRejected(doc);
  },
  'requireWellFormed: true on PI with invalid XML Char (\\x00) in data throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('foo', 'data' + String.fromCharCode(0) + 'here'));
    assertPIRejected(doc);
  },
  'requireWellFormed: true on PI with "?>" in data throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('foo', 'inject?>evil'));
    assertPIRejected(doc);
  },
  'requireWellFormed: true on PI with clean target and data does not throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('xml-stylesheet', 'href="style.css"'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<root><?xml-stylesheet href="style.css"?></root>');
  },
  'mutation vector: set PI data to "?>" then requireWellFormed: true throws InvalidStateError': function() {
    var doc = createRootDocument();
    var pi = doc.createProcessingInstruction('foo', 'clean');
    doc.documentElement.appendChild(pi);
    pi.data = 'inject?>evil';
    assertPIRejected(doc);
  }
}).addBatch({
  // the advisory's proof of concept, and every way to get the payload into a processing instruction
  'advisory PoC: injected element survives a default round-trip': function() {
    var doc = new DOMParser().parseFromString('<root/>', 'text/xml');
    doc.documentElement.appendChild(doc.createProcessingInstruction('a', PI_PAYLOAD));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><?a ?><injected/><?q ?></root>');
    assert.strictEqual(isInjected(doc.documentElement), true);
  },
  'advisory PoC: createProcessingInstruction payload throws with requireWellFormed: true': function() {
    var doc = new DOMParser().parseFromString('<root/>', 'text/xml');
    doc.documentElement.appendChild(doc.createProcessingInstruction('a', PI_PAYLOAD));
    assertPIRejected(doc);
  },
  '.textContent assignment payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var pi = doc.createProcessingInstruction('a', 'safe');
    doc.documentElement.appendChild(pi);
    pi.textContent = PI_PAYLOAD;
    assert.strictEqual(isInjected(doc.documentElement), true);
    assertPIRejected(doc);
  },
  'payload in a parsed document PI throws with requireWellFormed: true': function() {
    var doc = new DOMParser().parseFromString('<root><?a safe?></root>', 'text/xml');
    doc.documentElement.firstChild.data = PI_PAYLOAD;
    assertPIRejected(doc);
  },
  'payload in a nested PI throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var child = doc.createElement('child');
    doc.documentElement.appendChild(child);
    child.appendChild(doc.createProcessingInstruction('a', PI_PAYLOAD));
    assertPIRejected(doc);
  },
  'payload in a document level PI throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    doc.insertBefore(doc.createProcessingInstruction('a', PI_PAYLOAD), doc.documentElement);
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<?a ?><injected/><?q ?><root/>');
    assertPIRejected(doc);
  },
  'payload in a DocumentFragment PI throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var fragment = doc.createDocumentFragment();
    fragment.appendChild(doc.createProcessingInstruction('a', PI_PAYLOAD));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(fragment, false, null, { requireWellFormed: true });
    });
  },
  'node.toString and NodeList.toString with requireWellFormed: true on a PI payload throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('a', PI_PAYLOAD));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.toString(false, null, { requireWellFormed: true });
    });
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.documentElement.firstChild.toString(false, null, { requireWellFormed: true });
    });
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.documentElement.childNodes.toString(false, null, { requireWellFormed: true });
    });
  }
}).addBatch({
  // the target is not validated by createProcessingInstruction either, and is a writable
  // property: "?>" in it closes the processing instruction just like in the data
  'target injection: payload in the target survives a default round-trip': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('a?><injected/><?q', 'x'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><?a?><injected/><?q x?></root>');
    assert.strictEqual(isInjected(doc.documentElement), true);
  },
  'target injection: createProcessingInstruction payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('a?><injected/><?q', 'x'));
    assertPIRejected(doc);
  },
  'target injection: .target assignment payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var pi = doc.createProcessingInstruction('a', 'x');
    doc.documentElement.appendChild(pi);
    pi.target = 'a?><injected/><?q';
    assertPIRejected(doc);
  },
  'requireWellFormed: true on PI with a target that is not an XML Name throws': function() {
    var targets = ['', 'a b', 'a?>', '1a', 'a' + String.fromCharCode(0x0A)];
    for (var i = 0; i < targets.length; i++) {
      var doc = createRootDocument();
      doc.documentElement.appendChild(doc.createProcessingInstruction(targets[i], 'data'));
      assertPIRejected(doc);
    }
  },
  'requireWellFormed: true on PI data with an unpaired surrogate or U+FFFE throws': function() {
    var data = ['a' + String.fromCharCode(0xD800) + 'b', 'a' + String.fromCharCode(0xDC00), 'a' + String.fromCharCode(0xFFFE)];
    for (var i = 0; i < data.length; i++) {
      var doc = createRootDocument();
      doc.documentElement.appendChild(doc.createProcessingInstruction('foo', data[i]));
      assertPIRejected(doc);
    }
  },
  'requireWellFormed: true accepts well-formed targets and data': function() {
    var doc = createRootDocument();
    var data = 'smile ' + String.fromCharCode(0xD83D, 0xDE00) + ' tab\tnewline\n ? > ?';
    doc.documentElement.appendChild(doc.createProcessingInstruction('_x-1.y', data));
    doc.documentElement.appendChild(doc.createProcessingInstruction('xml-stylesheet', ''));
    doc.documentElement.appendChild(doc.createProcessingInstruction('xmlfoo', 'a'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<root><?_x-1.y ' + data + '?><?xml-stylesheet ?><?xmlfoo a?></root>');
  },
  'requireWellFormed: true on a parsed well-formed PI round-trips': function() {
    var xml = '<root><?xml-stylesheet href="a.xsl" type="text/xsl"?><child/></root>';
    var doc = new DOMParser().parseFromString(xml, 'text/xml');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }), xml);
  },
  'requireWellFormed: false keeps the verbatim PI output': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createProcessingInstruction('foo', 'inject?>evil'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: false }),
      '<root><?foo inject?>evil?></root>');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, null),
      '<root><?foo inject?>evil?></root>');
  }
}).addBatch({
  // CVE-2026-83607: element names are not validated when the element is created and were
  // serialized as is, even with requireWellFormed: true, so a crafted name could end the start
  // tag early and inject attributes or markup.
  // https://github.com/xmldom/xmldom/security/advisories/GHSA-w2rr-34g9-rvrj
  'default: element with invalid name emits verbatim - no throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createElement('x><inject'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><x><inject/></root>');
  },
  'requireWellFormed: true on element with invalid name throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createElement('x><inject'));
    assertNameRejected(doc);
  },
  'requireWellFormed: true on element with valid name does not throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createElement('child'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<root><child/></root>');
  }
}).addBatch({
  // CVE-2026-83605: Element.setAttribute() does not validate the attribute name and the
  // serializer emitted it as is, even with requireWellFormed: true, so a crafted name could
  // close the intended attribute and inject more attributes (event handlers included).
  // https://github.com/xmldom/xmldom/security/advisories/GHSA-4w3w-2rp5-g8jm
  'default: attribute with invalid name emits verbatim - no throw': function() {
    var doc = createRootDocument();
    doc.documentElement.setAttribute('a><inject ', 'v');
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root a><inject ="v"/>');
  },
  'requireWellFormed: true on attribute with invalid name throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.setAttribute('a><inject ', 'v');
    assertNameRejected(doc);
  },
  'requireWellFormed: true on attribute with valid name does not throw': function() {
    var doc = createRootDocument();
    doc.documentElement.setAttribute('class', 'hello');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<root class="hello"/>');
  }
}).addBatch({
  // the namespace prefix of an element or attribute is a writable property, and the
  // synthesized xmlns:PREFIX declaration was emitted with the prefix as is
  'default: invalid prefix in synthesized xmlns declaration emits verbatim - no throw': function() {
    var doc = createRootDocument();
    var el = doc.createElementNS('http://example.com/ns', 'p:child');
    doc.documentElement.appendChild(el);
    el.prefix = 'evil>';
    assert.strictEqual(new XMLSerializer().serializeToString(doc),
      '<root><p:child xmlns:evil>="http://example.com/ns"/></root>');
  },
  'requireWellFormed: true on invalid prefix in synthesized xmlns declaration throws InvalidStateError': function() {
    var doc = createRootDocument();
    var el = doc.createElementNS('http://example.com/ns', 'p:child');
    doc.documentElement.appendChild(el);
    el.prefix = 'evil>';
    assertNameRejected(doc);
  },
  'requireWellFormed: true on invalid prefix in element qualified name throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createElement('evil>:child'));
    assertNameRejected(doc);
  },
  'requireWellFormed: true on element with valid prefix does not throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createElementNS('http://example.com/ns', 'p:child'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<root><p:child xmlns:p="http://example.com/ns"/></root>');
  }
}).addBatch({
  // the advisories' proofs of concept, and the other ways to get a crafted name to the serializer
  'attribute advisory PoC: injected event handler survives a default round-trip': function() {
    var doc = createRootDocument();
    doc.documentElement.setAttribute(ATTRIBUTE_NAME_PAYLOAD, 'alert(1)');
    var xml = new XMLSerializer().serializeToString(doc);
    assert.strictEqual(xml, '<root class="safe" onclick="alert(1)"/>');
    var reparsed = new DOMParser().parseFromString(xml, 'text/xml');
    assert.strictEqual(reparsed.documentElement.getAttribute('onclick'), 'alert(1)');
  },
  'attribute advisory PoC: setAttribute payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    doc.documentElement.setAttribute(ATTRIBUTE_NAME_PAYLOAD, 'alert(1)');
    assertNameRejected(doc);
  },
  'element advisory PoC: injected event handler is emitted by default': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createElement(ELEMENT_NAME_PAYLOAD));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><img src=x onerror="alert(1)"/></root>');
  },
  'element advisory PoC: createElement payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createElement(ELEMENT_NAME_PAYLOAD));
    assertNameRejected(doc);
  },
  'attribute name payload through createAttribute, setAttributeNS and createAttributeNS throws': function() {
    var doc = createRootDocument();
    var attr = doc.createAttribute(ATTRIBUTE_NAME_PAYLOAD);
    attr.value = attr.nodeValue = 'alert(1)';
    doc.documentElement.setAttributeNode(attr);
    assertNameRejected(doc);

    doc = createRootDocument();
    doc.documentElement.setAttributeNS('urn:x', 'p:a="1" onclick', 'alert(1)');
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root xmlns:p="urn:x" p:a="1" onclick="alert(1)"/>');
    assertNameRejected(doc);

    doc = createRootDocument();
    attr = doc.createAttributeNS('urn:x', 'p:a><injected/');
    attr.value = attr.nodeValue = 'v';
    doc.documentElement.setAttributeNodeNS(attr);
    assertNameRejected(doc);
  },
  'element name payload through createElementNS throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createElementNS('urn:x', 'p:x onclick="alert(1)"'));
    assertNameRejected(doc);
  },
  'invalid attribute prefix in synthesized xmlns declaration throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    doc.documentElement.setAttributeNS('urn:x', 'p:a', 'v');
    doc.documentElement.getAttributeNodeNS('urn:x', 'a').prefix = 'x="1" onclick';
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root xmlns:x="1" onclick="urn:x" p:a="v"/>');
    assertNameRejected(doc);
  },
  'crafted names in nested elements and DocumentFragments throw with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var child = doc.createElement('child');
    doc.documentElement.appendChild(child);
    var grandchild = doc.createElement('grandchild');
    child.appendChild(grandchild);
    grandchild.setAttribute(ATTRIBUTE_NAME_PAYLOAD, 'alert(1)');
    assertNameRejected(doc);

    var fragment = doc.createDocumentFragment();
    fragment.appendChild(doc.createElement(ELEMENT_NAME_PAYLOAD));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(fragment, false, null, { requireWellFormed: true });
    });
  },
  'node.toString and NodeList.toString with requireWellFormed: true on a crafted name throw': function() {
    var doc = createRootDocument();
    doc.documentElement.setAttribute(ATTRIBUTE_NAME_PAYLOAD, 'alert(1)');
    doc.documentElement.appendChild(doc.createElement(ELEMENT_NAME_PAYLOAD));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.toString(false, null, { requireWellFormed: true });
    });
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.documentElement.getAttributeNode(ATTRIBUTE_NAME_PAYLOAD).toString(false, null, { requireWellFormed: true });
    });
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.documentElement.firstChild.toString(false, null, { requireWellFormed: true });
    });
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.documentElement.childNodes.toString(false, null, { requireWellFormed: true });
    });
  },
  'requireWellFormed: true on a parsed well-formed namespaced document round-trips': function() {
    var xml = '<root xmlns="urn:a" xmlns:p="urn:p" p:attr="1" xml:lang="en"><p:child _x-1.y="2"/><r\u00E9sum\u00E9/></root>';
    var doc = new DOMParser().parseFromString(xml, 'text/xml');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }), xml);
  },
  'requireWellFormed: false keeps the verbatim element and attribute names': function() {
    var doc = createRootDocument();
    doc.documentElement.setAttribute(ATTRIBUTE_NAME_PAYLOAD, 'alert(1)');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: false }),
      '<root class="safe" onclick="alert(1)"/>');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, null),
      '<root class="safe" onclick="alert(1)"/>');
  }
}).addBatch({
  // CVE-2026-83610: the EntityReference nodeName was serialized as is between "&" and ";",
  // even with requireWellFormed: true, so a crafted name could inject markup.
  'default: EntityReference serializes as &name;': function() {
    var doc = new DOMImplementation().createDocument(null, '');
    var entityRef = doc.createEntityReference('amp');
    assert.strictEqual(new XMLSerializer().serializeToString(entityRef), '&amp;');
  },
  'requireWellFormed: true on valid EntityReference serializes as &name;': function() {
    var doc = new DOMImplementation().createDocument(null, '');
    var entityRef = doc.createEntityReference('amp');
    assert.strictEqual(new XMLSerializer().serializeToString(entityRef, false, null, { requireWellFormed: true }), '&amp;');
  },
  'default: EntityReference with ill-formed nodeName emits verbatim - no throw': function() {
    var doc = new DOMImplementation().createDocument(null, '');
    var entityRef = doc.createEntityReference('safe');
    // bypass the creation time check through a direct nodeName write
    entityRef.nodeName = 'safe; <injected/> &x';
    assert.strictEqual(new XMLSerializer().serializeToString(entityRef), '&safe; <injected/> &x;');
  },
  'requireWellFormed: true on EntityReference with ill-formed nodeName throws InvalidStateError': function() {
    var doc = new DOMImplementation().createDocument(null, '');
    var entityRef = doc.createEntityReference('safe');
    entityRef.nodeName = 'safe; <injected/> &x';
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(entityRef, false, null, { requireWellFormed: true });
    });
  },
  'round-trip: valid EntityReference serializes to &name; and re-parses': function() {
    var doc = new DOMImplementation().createDocument(null, 'root');
    var entityRef = doc.createEntityReference('amp');
    var serialized = new XMLSerializer().serializeToString(entityRef, false, null, { requireWellFormed: true });
    assert.strictEqual(serialized, '&amp;');
    var reparsed = new DOMParser().parseFromString('<root>' + serialized + '</root>', 'text/xml');
    assert.strictEqual(reparsed.documentElement.textContent, '&');
  }
}).addBatch({
  // the injection vectors: the crafted name is emitted as live markup by default and is
  // rejected with requireWellFormed: true
  'entity reference PoC: injected element survives a default round-trip': function() {
    var doc = createRootDocument();
    var entityRef = doc.createEntityReference('amp');
    doc.documentElement.appendChild(entityRef);
    entityRef.nodeName = ENTITY_REFERENCE_NAME_PAYLOAD;
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root>&amp;<injected/>&amp;</root>');
    assert.strictEqual(isInjected(doc.documentElement), true);
  },
  'entity reference PoC: createEntityReference payload throws InvalidCharacterError': function() {
    var doc = createRootDocument();
    assertThrowsDOMException(INVALID_CHARACTER_ERR, function() {
      doc.createEntityReference(ENTITY_REFERENCE_NAME_PAYLOAD);
    });
  },
  'nodeName assignment payload in a document throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var entityRef = doc.createEntityReference('amp');
    doc.documentElement.appendChild(entityRef);
    entityRef.nodeName = ENTITY_REFERENCE_NAME_PAYLOAD;
    assertEntityReferenceRejected(doc);
  },
  'payload in a nested EntityReference throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var child = doc.createElement('child');
    doc.documentElement.appendChild(child);
    var entityRef = doc.createEntityReference('amp');
    child.appendChild(entityRef);
    entityRef.nodeName = ENTITY_REFERENCE_NAME_PAYLOAD;
    assertEntityReferenceRejected(doc);
  },
  'node.toString and NodeList.toString with requireWellFormed: true on an EntityReference payload throw': function() {
    var doc = createRootDocument();
    var entityRef = doc.createEntityReference('amp');
    doc.documentElement.appendChild(entityRef);
    entityRef.nodeName = ENTITY_REFERENCE_NAME_PAYLOAD;
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.toString(false, null, { requireWellFormed: true });
    });
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      entityRef.toString(false, null, { requireWellFormed: true });
    });
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.documentElement.childNodes.toString(false, null, { requireWellFormed: true });
    });
  },
  'requireWellFormed: true on EntityReference names that are not XML Names throws': function() {
    var names = ['', 'a b', '1a', 'a;b', 'a' + String.fromCharCode(0x0A)];
    for (var i = 0; i < names.length; i++) {
      var doc = createRootDocument();
      var entityRef = doc.createEntityReference('amp');
      doc.documentElement.appendChild(entityRef);
      entityRef.nodeName = names[i];
      assertEntityReferenceRejected(doc);
    }
  },
  'requireWellFormed: true accepts EntityReferences with valid names in a document': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createEntityReference('amp'));
    doc.documentElement.appendChild(doc.createEntityReference('_x-1.y'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<root>&amp;&_x-1.y;</root>');
  },
  'requireWellFormed: false keeps the verbatim EntityReference output': function() {
    var doc = createRootDocument();
    var entityRef = doc.createEntityReference('amp');
    doc.documentElement.appendChild(entityRef);
    entityRef.nodeName = ENTITY_REFERENCE_NAME_PAYLOAD;
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: false }),
      '<root>&amp;<injected/>&amp;</root>');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, null),
      '<root>&amp;<injected/>&amp;</root>');
  }
}).run();

// Serializing `doc` with requireWellFormed throws, so the EntityReference payload never reaches the output.
function assertEntityReferenceRejected(doc) {
  assertThrowsDOMException(INVALID_STATE_ERR, function() {
    new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
  });
}

// Serializing `doc` with requireWellFormed throws, so the crafted element or attribute name never reaches the output.
function assertNameRejected(doc) {
  assertThrowsDOMException(INVALID_STATE_ERR, function() {
    new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
  });
}

// Serializing `doc` with requireWellFormed throws, so the payload never reaches the output.
function assertCommentRejected(doc) {
  assertThrowsDOMException(INVALID_STATE_ERR, function() {
    new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
  });
}

// Serializing `doc` with requireWellFormed throws, so the ProcessingInstruction payload never reaches the output.
function assertPIRejected(doc) {
  assertThrowsDOMException(INVALID_STATE_ERR, function() {
    new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
  });
}
