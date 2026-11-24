var wows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;
var XMLSerializer = require('xmldom').XMLSerializer;

// CVE-2021-32796: namespace declarations synthesized by the serializer must
// escape their value like any other attribute value.
function quietParser() {
  return new DOMParser({errorHandler: {warning: function () {}, error: function () {}, fatalError: function () {}}});
}

wows.describe('XML Serializer attribute escaping').addBatch({
  'should escape special characters in namespace attributes': function () {
    var input = '<xml xmlns=\'<&"\' xmlns:attr=\'"&<\'><test attr:test=""/></xml>';
    var doc = new DOMParser().parseFromString(input, 'text/xml');

    // in this case the explicit attribute nodes are serialized
    assert.equal(new XMLSerializer().serializeToString(doc),
      '<xml xmlns="&lt;&amp;&quot;" xmlns:attr="&quot;&amp;&lt;"><test attr:test=""/></xml>');

    // in this case the namespace attributes are "inherited" from the parent,
    // which is not serialized
    assert.equal(new XMLSerializer().serializeToString(doc.documentElement.firstChild),
      '<test xmlns:attr="&quot;&amp;&lt;" attr:test="" xmlns="&lt;&amp;&quot;"/>');
  },
  'unbound prefix from a lenient parse still serializes xmlns:p=""': function () {
    var doc = quietParser().parseFromString('<p:a/>', 'text/xml');
    var out = new XMLSerializer().serializeToString(doc);
    assert.ok(out.indexOf('xmlns:p=""') !== -1, out);
    assert.equal(doc.toString(), out);
  },
  'createElementNS(null, "p:b") serializes xmlns:p=""': function () {
    var doc = new DOMParser().parseFromString('<r/>', 'text/xml');
    var el = doc.createElementNS(null, 'p:b');
    doc.documentElement.appendChild(el);
    assert.equal(el.toString(), '<p:b xmlns:p=""/>');
    assert.ok(new XMLSerializer().serializeToString(doc).indexOf('<p:b xmlns:p=""/>') !== -1);
  },
  'createAttributeNS(null, "p:b") serializes xmlns:p=""': function () {
    var doc = new DOMParser().parseFromString('<r/>', 'text/xml');
    var attr = doc.createAttributeNS(null, 'p:b');
    attr.value = 'v';
    doc.documentElement.setAttributeNode(attr);
    var out = new XMLSerializer().serializeToString(doc);
    assert.equal(out, '<r xmlns:p="" p:b="v"/>');
    assert.equal(doc.toString(), out);
  }
}).run();
