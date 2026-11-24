/**
 * @typedef ErrorReport
 * @property {string} source the XML snippet
 * @property {'error'|'warning'|'fatalError'} level the name of the method triggered
 * @property {?function(msg:string):boolean} match to pick the relevant report when there are multiple
 * @property {?boolean} skippedInHtml Is the error reported when parsing HTML?
 */
/**
 * A collection of XML samples and related information that cause the XMLReader
 * to call methods on `errorHandler`.
 *
 * Ported from the xmldom 0.5.0 catalog (CVE-2021-21366). Every upstream entry is
 * reported by this version; the differences are:
 * - WF_DuplicateAttribute: level 'error' instead of 'fatalError', a redefined attribute
 *   is reported without stopping the parser (its last value wins).
 * - WF_AttributeMissingQuote and WF_AttributeMissingQuote2: `match` picks the message by the
 *   reported value; upstream told them apart by `missed quot(")!` vs `!!`, but here both
 *   messages keep their `!!`.
 * - WF_EndTagCaseMismatch: added, it is the only sample reported as 'fatalError' once
 *   duplicate attributes are reported as 'error'.
 *
 * @type {Object<string, ErrorReport>}
 */
var REPORTED = {
	/**
	 * Entities need to be in the entityMap to be converted as part of parsing.
	 * xmldom currently doesn't parse entities declared in DTD.
	 *
	 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#wf-entdeclared
	 * @see https://www.w3.org/TR/2006/REC-xml11-20060816/#wf-entdeclared
	 */
	WF_EntityDeclared: {
		source: '<xml>&e;</xml>',
		level: 'error',
		match: function (msg) { return /entity not found/.test(msg); }
	},
	/**
	 * Well-formedness constraint: Unique Att Spec
	 *
	 * An attribute name must not appear more than once
	 * in the same start-tag or empty-element tag.
	 *
	 * In the browser:
	 * - as XML it is reported as `error on line 1 at column 17: Attribute a redefined`
	 * - as HTML only the first definition is considered
	 *
	 * xmldom used the first declaration of a namespace but the last value of the attribute,
	 * which can be a security issue (CVE-2021-21366).
	 * Now the last value is used for both, and the redefinition is reported as error.
	 *
	 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#uniqattspec
	 * @see https://www.w3.org/TR/2006/REC-xml11-20060816/#uniqattspec
	 */
	WF_DuplicateAttribute: {
		source: '<xml a="1" a="2"></xml>',
		level: 'error',
		match: function (msg) { return /Attribute .* redefined/.test(msg); }
	},
	/**
	 * Well-formedness constraint: Element Type Match
	 *
	 * An end tag that only matches the start tag when ignoring the case
	 * still closes the element, but is reported as fatalError.
	 * (The trailing `</xml>` keeps `<xml>` from being treated as an unclosed tag.)
	 *
	 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#GIMatch
	 */
	WF_EndTagCaseMismatch: {
		source: '<xml></XML></xml>',
		level: 'fatalError',
		match: function (msg) { return /is not match the current start tagName/.test(msg); }
	},
	/**
	 * This sample doesn't follow the specified grammar.
	 * In the browser it is reported as `error on line 1 at column 14: expected '>'`,
	 * but still adds the root level element to the dom.
	 */
	SYNTAX_EndTagNotComplete: {
		source: '<xml></xml',
		level: 'error',
		match: function (msg) { return /end tag name/.test(msg) && /is not complete/.test(msg); }
	},
	/**
	 * This sample doesn't follow the specified grammar.
	 * In the browser it is reported as `error on line 1 at column 21: expected '>'`,
	 * but still adds the root level element and inner tag to the dom.
	 */
	SYNTAX_EndTagMaybeNotComplete: {
		source: '<xml><inner></inner </xml>',
		level: 'error',
		match: function (msg) { return /end tag name/.test(msg) && /maybe not complete/.test(msg); }
	},
	/**
	 * The XML `ETag` production is `'</' Name S? '>'`: a valid `Name` followed by whitespace and
	 * non-whitespace residue (e.g. `</a\nbogus>`) is not well-formed. It was historically accepted
	 * silently; it is now reported as a recoverable `error` while parsing recovers unchanged.
	 *
	 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-ETag
	 */
	WF_EndTagTrailingContent: {
		source: '<a></a\nbogus>',
		level: 'error',
		match: function (msg) { return /end tag name is followed by whitespace and trailing content/.test(msg); }
	},
	/**
	 * This sample doesn't follow the specified grammar.
	 * In the browser it is reported as `error on line 1 at column 6: Comment not terminated`.
	 */
	SYNTAX_UnclosedComment: {
		source: '<!--',
		level: 'error',
		match: function (msg) { return /Unclosed comment/.test(msg); }
	},
	/**
	 * Thrown by ElementAttributes.setTagName, caught in parse.
	 * This sample doesn't follow the specified grammar.
	 * In the browser:
	 * - as XML it is reported as
	 * `error on line 1 at column 2: StartTag: invalid element name`
	 * - as HTML it is accepted as characters
	 */
	SYNTAX_InvalidTagName: {
		source: '<123 />',
		level: 'error',
		match: function (msg) { return /invalid tagName/.test(msg); }
	},
	/**
	 * Thrown by ElementAttributes.add, caught in parse.
	 * This sample doesn't follow the specified grammar.
	 * In the browser:
	 * - as XML it is reported as
	 * `error on line 1 at column 6: error parsing attribute name`
	 * - as HTML it is accepted as attribute name
	 */
	SYNTAX_InvalidAttributeName: {
		source: '<xml 123=""/>',
		level: 'error',
		match: function (msg) { return /invalid attribute/.test(msg); }
	},
	/**
	 * This sample doesn't follow the specified grammar.
	 * In the browser it is reported as `error on line 1 at column 5: Couldn't find end of Start Tag xml`.
	 */
	SYNTAX_UnexpectedEndOfInput: {
		source: '<xml',
		level: 'error',
		match: function (msg) { return /unexpected end of input/.test(msg); }
	},
	/**
	 * Thrown by parseElementStartPart, caught in parse.
	 * This sample doesn't follow the specified grammar.
	 * In the browser:
	 * - in XML it is reported as `error on line 1 at column 8: error parsing attribute name`
	 * - in HTML it produces `<xml><a <="" xml=""></a></xml>` (invalid XML?)
	 */
	SYNTAX_ElementClosingNotConnected: {
		source: '<xml><a/ </xml>',
		level: 'error',
		match: function (msg) { return /must be connected/.test(msg); }
	},
	/**
	 * In the Browser (for XML) this is reported as
	 * `error on line 1 at column 6: Extra content at the end of the document`
	 * for HTML it's added to the DOM without anything being reported.
	 */
	WF_UnclosedXmlAttribute: {
		source: '<xml>',
		level: 'warning',
		skippedInHtml: true,
		match: function (msg) { return /unclosed xml attribute/.test(msg); }
	},
	/**
	 * In the browser:
	 * - for XML it is reported as
	 * `error on line 1 at column 10: Specification mandates value for attribute attr`
	 * - for HTML is uses the attribute as one with no value and adds `"value"` to the attribute name
	 *   and is not reporting any issue.
	 */
	WF_AttributeValueMustAfterEqual: {
		source: '<xml attr"value" />',
		level: 'warning',
		match: function (msg) { return /attribute value must after "="/.test(msg); }
	},
	/**
	 * In the browser:
	 * - for XML it is reported as `error on line 1 at column 11: AttValue: " or ' expected`
	 * - for HTML is wraps `value"` with quotes and is not reporting any issue.
	 */
	WF_AttributeMissingStartingQuote: {
		source: '<xml attr=value" />',
		level: 'warning',
		match: function (msg) { return /missed start quot/.test(msg); }
	},
	/**
	 * Thrown by parseElementStartPart, caught in parse.
	 *
	 * In the browser:
	 * - for XML it is reported as `error on line 1 at column 20: AttValue: ' expected`
	 * - for HTML nothing is added to the DOM.
	 */
	SYNTAX_AttributeMissingEndingQuote: {
		source: '<xml attr="value />',
		level: 'error',
		match: function (msg) { return /attribute value no end .* match/.test(msg); }
	},
	/**
	 * Reported when the unquoted value is ended by the end of the tag.
	 * In the browser:
	 * - for XML it is reported as `error on line 1 at column 11: AttValue: " or ' expected`
	 * - for HTML is wraps `value/` with quotes and is not reporting any issue.
	 */
	WF_AttributeMissingQuote: {
		source: '<xml attr=value/>',
		level: 'warning',
		match: function (msg) { return /attribute "value" missed quot/.test(msg); }
	},
	/**
	 * Reported when the unquoted value is ended by a space.
	 * This is the only warning reported in this sample.
	 * For some reason the "attribute" that is reported as missing quotes
	 * has the name `&`.
	 *
	 * In the browser:
	 * - for XML it is reported as `error on line 1 at column 8: AttValue: " or ' expected`
	 * - for HTML is yields `<xml a="&amp;" b="&amp;"></xml>` and is not reporting any issue.
	 */
	WF_AttributeMissingQuote2: {
		source: '<xml a=& b="&"/>',
		level: 'warning',
		match: function (msg) { return /attribute "&" missed quot/.test(msg); }
	},
	/**
	 * In the browser:
	 * - for XML it is reported as `error on line 1 at column 9: AttValue: " or ' expected`
	 * - for HTML is yields `<doc a1></xml>` and is not reporting any issue.
	 *
	 * But the XML specifications does not allow that:
	 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-Attribute
	 * @see https://www.w3.org/TR/2006/REC-xml11-20060816/#NT-Attribute
	 */
	SYNTAX_AttributeEqualMissingValue: {
		source: '<doc a1=></doc>',
		level: 'error',
		match: function (msg) { return /attribute value missed!!/.test(msg); }
	},
	/**
	 * In the browser this is not an issue at all, but just add an attribute without a value.
	 * But the XML specifications does not allow that:
	 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-Attribute
	 * @see https://www.w3.org/TR/2006/REC-xml11-20060816/#NT-Attribute
	 */
	WF_AttributeMissingValue: {
		source: '<xml attr ></xml>',
		level: 'warning',
		match: function (msg) { return /missed value/.test(msg) && /instead!!/.test(msg); }
	},
	/**
	 * This seems to only be reached when there are two subsequent attributes with a missing value
	 * In the browser this is not an issue at all, but just add an attribute without a value.
	 * But the XML specifications does not allow that:
	 * @see https://www.w3.org/TR/2008/REC-xml-20081126/#NT-Attribute
	 * @see https://www.w3.org/TR/2006/REC-xml11-20060816/#NT-Attribute
	 */
	WF_AttributeMissingValue2: {
		source: '<xml attr attr2 ></xml>',
		level: 'warning',
		match: function (msg) { return /missed value/.test(msg) && /instead2!!/.test(msg); }
	}
};

module.exports = {
	REPORTED: REPORTED
};
