/*
 * DOM Level 2
 * Object DOMException
 * @see http://www.w3.org/TR/REC-DOM-Level-1/ecma-script-language-binding.html
 * @see http://www.w3.org/TR/2000/REC-DOM-Level-2-Core-20001113/ecma-script-binding.html
 */

function copy(src,dest){
	for(var p in src){
		if (Object.prototype.hasOwnProperty.call(src, p)) {
			dest[p] = src[p];
		}
	}
}

/**
 * Ponyfill for `Array.prototype.find` which is only available in ES6 runtimes.
 *
 * Works with anything that has a `length` property and index access properties, including NodeList.
 *
 * @template {unknown} T
 * @param {Array<T> | ({length:number, [number]: T})} list
 * @param {function (item: T, index: number, list:Array<T> | ({length:number, [number]: T})):boolean} predicate
 * @param {Partial<Pick<ArrayConstructor['prototype'], 'find'>>?} ac `Array.prototype` by default,
 * 				allows injecting a custom implementation in tests
 * @returns {T | undefined}
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/find
 * @see https://tc39.es/ecma262/multipage/indexed-collections.html#sec-array.prototype.find
 */
function find(list, predicate, ac) {
	if (ac === undefined) {
		ac = Array.prototype;
	}
	if (list && typeof ac.find === 'function') {
		return ac.find.call(list, predicate);
	}
	for (var i = 0; i < list.length; i++) {
		if (Object.prototype.hasOwnProperty.call(list, i)) {
			var item = list[i];
			if (predicate.call(undefined, item, i, list)) {
				return item;
			}
		}
	}
}
/**
^\w+\.prototype\.([_\w]+)\s*=\s*((?:.*\{\s*?[\r\n][\s\S]*?^})|\S.*?(?=[;\r\n]));?
^\w+\.prototype\.([_\w]+)\s*=\s*(\S.*?(?=[;\r\n]));?
 */
function _extends(Class,Super){
	var pt = Class.prototype;
	if(Object.create){
		var ppt = Object.create(Super.prototype)
		pt.__proto__ = ppt;
	}
	if(!(pt instanceof Super)){
		function t(){};
		t.prototype = Super.prototype;
		t = new t();
		copy(pt,t);
		Class.prototype = pt = t;
	}
	if(pt.constructor != Class){
		if(typeof Class != 'function'){
			console.error("unknow Class:"+Class)
		}
		pt.constructor = Class
	}
}
var htmlns = 'http://www.w3.org/1999/xhtml' ;
// Node Types
var NodeType = {}
var ELEMENT_NODE                = NodeType.ELEMENT_NODE                = 1;
var ATTRIBUTE_NODE              = NodeType.ATTRIBUTE_NODE              = 2;
var TEXT_NODE                   = NodeType.TEXT_NODE                   = 3;
var CDATA_SECTION_NODE          = NodeType.CDATA_SECTION_NODE          = 4;
var ENTITY_REFERENCE_NODE       = NodeType.ENTITY_REFERENCE_NODE       = 5;
var ENTITY_NODE                 = NodeType.ENTITY_NODE                 = 6;
var PROCESSING_INSTRUCTION_NODE = NodeType.PROCESSING_INSTRUCTION_NODE = 7;
var COMMENT_NODE                = NodeType.COMMENT_NODE                = 8;
var DOCUMENT_NODE               = NodeType.DOCUMENT_NODE               = 9;
var DOCUMENT_TYPE_NODE          = NodeType.DOCUMENT_TYPE_NODE          = 10;
var DOCUMENT_FRAGMENT_NODE      = NodeType.DOCUMENT_FRAGMENT_NODE      = 11;
var NOTATION_NODE               = NodeType.NOTATION_NODE               = 12;

// ExceptionCode
var ExceptionCode = {}
var ExceptionMessage = {};
var INDEX_SIZE_ERR              = ExceptionCode.INDEX_SIZE_ERR              = ((ExceptionMessage[1]="Index size error"),1);
var DOMSTRING_SIZE_ERR          = ExceptionCode.DOMSTRING_SIZE_ERR          = ((ExceptionMessage[2]="DOMString size error"),2);
var HIERARCHY_REQUEST_ERR       = ExceptionCode.HIERARCHY_REQUEST_ERR       = ((ExceptionMessage[3]="Hierarchy request error"),3);
var WRONG_DOCUMENT_ERR          = ExceptionCode.WRONG_DOCUMENT_ERR          = ((ExceptionMessage[4]="Wrong document"),4);
var INVALID_CHARACTER_ERR       = ExceptionCode.INVALID_CHARACTER_ERR       = ((ExceptionMessage[5]="Invalid character"),5);
var NO_DATA_ALLOWED_ERR         = ExceptionCode.NO_DATA_ALLOWED_ERR         = ((ExceptionMessage[6]="No data allowed"),6);
var NO_MODIFICATION_ALLOWED_ERR = ExceptionCode.NO_MODIFICATION_ALLOWED_ERR = ((ExceptionMessage[7]="No modification allowed"),7);
var NOT_FOUND_ERR               = ExceptionCode.NOT_FOUND_ERR               = ((ExceptionMessage[8]="Not found"),8);
var NOT_SUPPORTED_ERR           = ExceptionCode.NOT_SUPPORTED_ERR           = ((ExceptionMessage[9]="Not supported"),9);
var INUSE_ATTRIBUTE_ERR         = ExceptionCode.INUSE_ATTRIBUTE_ERR         = ((ExceptionMessage[10]="Attribute in use"),10);
//level2
var INVALID_STATE_ERR        	= ExceptionCode.INVALID_STATE_ERR        	= ((ExceptionMessage[11]="Invalid state"),11);
var SYNTAX_ERR               	= ExceptionCode.SYNTAX_ERR               	= ((ExceptionMessage[12]="Syntax error"),12);
var INVALID_MODIFICATION_ERR 	= ExceptionCode.INVALID_MODIFICATION_ERR 	= ((ExceptionMessage[13]="Invalid modification"),13);
var NAMESPACE_ERR            	= ExceptionCode.NAMESPACE_ERR           	= ((ExceptionMessage[14]="Invalid namespace"),14);
var INVALID_ACCESS_ERR       	= ExceptionCode.INVALID_ACCESS_ERR      	= ((ExceptionMessage[15]="Invalid access"),15);


function DOMException(code, message) {
	if(message instanceof Error){
		var error = message;
	}else{
		error = this;
		Error.call(this, ExceptionMessage[code]);
		this.message = ExceptionMessage[code];
		if(Error.captureStackTrace) Error.captureStackTrace(this, DOMException);
	}
	error.code = code;
	if(message) this.message = this.message + ": " + message;
	return error;
};
DOMException.prototype = Error.prototype;
copy(ExceptionCode,DOMException)
/**
 * @see http://www.w3.org/TR/2000/REC-DOM-Level-2-Core-20001113/core.html#ID-536297177
 * The NodeList interface provides the abstraction of an ordered collection of nodes, without defining or constraining how this collection is implemented. NodeList objects in the DOM are live.
 * The items in the NodeList are accessible via an integral index, starting from 0.
 */
function NodeList() {
};
NodeList.prototype = {
	/**
	 * The number of nodes in the list. The range of valid child node indices is 0 to length-1 inclusive.
	 * @standard level1
	 */
	length:0, 
	/**
	 * Returns the indexth item in the collection. If index is greater than or equal to the number of nodes in the list, this returns null.
	 * @standard level1
	 * @param index  unsigned long 
	 *   Index into the collection.
	 * @return Node
	 * 	The node at the indexth position in the NodeList, or null if that is not a valid index. 
	 */
	item: function(index) {
		return this[index] || null;
	},
	toString:function(isHTML,nodeFilter,options){
		var requireWellFormed = options != null ? !!options.requireWellFormed : false;
		for(var buf = [], i = 0;i<this.length;i++){
			serializeToString(this[i],buf,isHTML,nodeFilter,null,requireWellFormed);
		}
		return buf.join('');
	},
	/**
	 * @private
	 * @param {function (Node):boolean} predicate
	 * @returns {Node[]}
	 */
	filter: function (predicate) {
		return Array.prototype.filter.call(this, predicate);
	},
	/**
	 * @private
	 * @param {Node} item
	 * @returns {number}
	 */
	indexOf: function (item) {
		return Array.prototype.indexOf.call(this, item);
	}
};
function LiveNodeList(node,refresh){
	this._node = node;
	this._refresh = refresh
	_updateLiveList(this);
}
function _updateLiveList(list){
	var inc = list._node._inc || list._node.ownerDocument._inc;
	if(list._inc != inc){
		var ls = list._refresh(list._node);
		//console.log(ls.length)
		__set__(list,'length',ls.length);
		copy(ls,list);
		list._inc = inc;
	}
}
LiveNodeList.prototype.item = function(i){
	_updateLiveList(this);
	return this[i];
}

_extends(LiveNodeList,NodeList);
/**
 * 
 * Objects implementing the NamedNodeMap interface are used to represent collections of nodes that can be accessed by name. Note that NamedNodeMap does not inherit from NodeList; NamedNodeMaps are not maintained in any particular order. Objects contained in an object implementing NamedNodeMap may also be accessed by an ordinal index, but this is simply to allow convenient enumeration of the contents of a NamedNodeMap, and does not imply that the DOM specifies an order to these Nodes.
 * NamedNodeMap objects in the DOM are live.
 * used for attributes or DocumentType entities 
 */
function NamedNodeMap() {
	// nodeName -> Attr membership index; lets the parse-time de-duplication in
	// setNamedItem resolve an existing attribute in O(1) instead of scanning the
	// list, so building an element with M attributes costs O(M) rather than O(M^2).
	// The numbered entries and length remain the sole authority for attribute order.
	// Keys are prefixed (see _nnmIndexKey) and only read as own properties, so an
	// attribute named __proto__ or constructor is an ordinary key.
	this._nameIndex = {};
};

function _findNodeIndex(list,node){
	var i = list.length;
	while(i--){
		if(list[i] === node){return i}
	}
}

// '@' + nodeName: no key can be `__proto__` (special on every object, including
// null-prototype ones, in pre-ES2015 engines such as the V8 of node 0.10) or the
// name of an Object.prototype member.
function _nnmIndexKey(name) {
	return '@' + name;
}
function _nnmIndexGet(list, name) {
	var key = _nnmIndexKey(name);
	if (Object.prototype.hasOwnProperty.call(list._nameIndex, key)) {
		return list._nameIndex[key];
	}
}
function _nnmIndexAdd(list, attr) {
	list._nameIndex[_nnmIndexKey(attr.nodeName)] = attr;
}
function _nnmIndexRemove(list, attr) {
	// Only drop the entry if it still points at this attribute; a replacement with
	// a different nodeName may already have re-keyed it.
	if (_nnmIndexGet(list, attr.nodeName) === attr) {
		delete list._nameIndex[_nnmIndexKey(attr.nodeName)];
		// setNamedItemNS can leave two attributes with the same nodeName (same
		// qualified name, different namespaceURI): keep indexing the one still in the
		// list, so setNamedItem keeps replacing it instead of adding a duplicate.
		// Only reached on removal/replacement, which already scan the list.
		var other = list.getNamedItem(attr.nodeName);
		if (other) {
			_nnmIndexAdd(list, other);
		}
	}
}

function _addNamedNode(el,list,newAttr,oldAttr){
	if(oldAttr){
		list[_findNodeIndex(list,oldAttr)] = newAttr;
	}else{
		list[list.length++] = newAttr;
	}
	_nnmIndexAdd(list, newAttr);
	if(oldAttr){
		// oldAttr leaves the list; drop its index entry (its nodeName may differ
		// from newAttr's when the replacement came via setNamedItemNS).
		_nnmIndexRemove(list, oldAttr);
	}
	if(el){
		newAttr.ownerElement = el;
		var doc = el.ownerDocument;
		if(doc){
			oldAttr && _onRemoveAttribute(doc,el,oldAttr);
			_onAddAttribute(doc,el,newAttr);
		}
	}
}
function _removeNamedNode(el,list,attr){
	//console.log('remove attr:'+attr)
	var i = _findNodeIndex(list,attr);
	if(i>=0){
		var lastIndex = list.length-1
		while(i<lastIndex){
			list[i] = list[++i]
		}
		list.length = lastIndex;
		_nnmIndexRemove(list, attr);
		if(el){
			var doc = el.ownerDocument;
			if(doc){
				_onRemoveAttribute(doc,el,attr);
				attr.ownerElement = null;
			}
		}
	}else{
		throw new DOMException(NOT_FOUND_ERR,new Error(el.tagName+'@'+attr))
	}
}
NamedNodeMap.prototype = {
	length:0,
	item:NodeList.prototype.item,
	getNamedItem: function(key) {
//		if(key.indexOf(':')>0 || key == 'xmlns'){
//			return null;
//		}
		//console.log()
		var i = this.length;
		while(i--){
			var attr = this[i];
			//console.log(attr.nodeName,key)
			if(attr.nodeName == key){
				return attr;
			}
		}
	},
	setNamedItem: function(attr) {
		var el = attr.ownerElement;
		if(el && el!=this._ownerElement){
			throw new DOMException(INUSE_ATTRIBUTE_ERR);
		}
		// Resolve any existing attribute with the same nodeName through the O(1)
		// membership index rather than an O(M) scan — this is the parse-dedup hot
		// path (setAttributeNode per attribute during parse). Absent -> undefined,
		// matching getNamedItem's contract.
		var oldAttr = _nnmIndexGet(this, attr.nodeName);
		_addNamedNode(this._ownerElement,this,attr,oldAttr);
		return oldAttr;
	},
	/* returns Node */
	setNamedItemNS: function(attr) {// raises: WRONG_DOCUMENT_ERR,NO_MODIFICATION_ALLOWED_ERR,INUSE_ATTRIBUTE_ERR
		var el = attr.ownerElement, oldAttr;
		if(el && el!=this._ownerElement){
			throw new DOMException(INUSE_ATTRIBUTE_ERR);
		}
		oldAttr = this.getNamedItemNS(attr.namespaceURI,attr.localName);
		_addNamedNode(this._ownerElement,this,attr,oldAttr);
		return oldAttr;
	},

	/* returns Node */
	removeNamedItem: function(key) {
		var attr = this.getNamedItem(key);
		_removeNamedNode(this._ownerElement,this,attr);
		return attr;
		
		
	},// raises: NOT_FOUND_ERR,NO_MODIFICATION_ALLOWED_ERR
	
	//for level2
	removeNamedItemNS:function(namespaceURI,localName){
		var attr = this.getNamedItemNS(namespaceURI,localName);
		_removeNamedNode(this._ownerElement,this,attr);
		return attr;
	},
	getNamedItemNS: function(namespaceURI, localName) {
		var i = this.length;
		while(i--){
			var node = this[i];
			if(node.localName == localName && node.namespaceURI == namespaceURI){
				return node;
			}
		}
		return null;
	}
};
/**
 * @see http://www.w3.org/TR/REC-DOM-Level-1/level-one-core.html#ID-102161490
 */
function DOMImplementation(/* Object */ features) {
	this._features = {};
	if (features) {
		for (var feature in features) {
			 this._features = features[feature];
		}
	}
};

DOMImplementation.prototype = {
	hasFeature: function(/* string */ feature, /* string */ version) {
		var versions = this._features[feature.toLowerCase()];
		if (versions && (!version || version in versions)) {
			return true;
		} else {
			return false;
		}
	},
	// Introduced in DOM Level 2:
	createDocument:function(namespaceURI,  qualifiedName, doctype){// raises:INVALID_CHARACTER_ERR,NAMESPACE_ERR,WRONG_DOCUMENT_ERR
		var doc = new Document();
		doc.implementation = this;
		doc.childNodes = new NodeList();
		doc.doctype = doctype;
		if(doctype){
			doc.appendChild(doctype);
		}
		if(qualifiedName){
			var root = doc.createElementNS(namespaceURI,qualifiedName);
			doc.appendChild(root);
		}
		return doc;
	},
	// Introduced in DOM Level 2:
	createDocumentType:function(qualifiedName, publicId, systemId){// raises:INVALID_CHARACTER_ERR,NAMESPACE_ERR
		var node = new DocumentType();
		node.name = qualifiedName;
		node.nodeName = qualifiedName;
		node.publicId = publicId;
		node.systemId = systemId;
		// Introduced in DOM Level 2:
		//readonly attribute DOMString        internalSubset;
		
		//TODO:..
		//  readonly attribute NamedNodeMap     entities;
		//  readonly attribute NamedNodeMap     notations;
		return node;
	}
};


/**
 * @see http://www.w3.org/TR/2000/REC-DOM-Level-2-Core-20001113/core.html#ID-1950641247
 */

function Node() {
};

Node.prototype = {
	firstChild : null,
	lastChild : null,
	previousSibling : null,
	nextSibling : null,
	attributes : null,
	parentNode : null,
	childNodes : null,
	ownerDocument : null,
	nodeValue : null,
	namespaceURI : null,
	prefix : null,
	localName : null,
	// Modified in DOM Level 2:
	insertBefore:function(newChild, refChild){//raises 
		return _insertBefore(this,newChild,refChild);
	},
	replaceChild:function(newChild, oldChild){//raises
		_insertBefore(this, newChild,oldChild, assertPreReplacementValidityInDocument);
		if(oldChild){
			this.removeChild(oldChild);
		}
	},
	removeChild:function(oldChild){
		return _removeChild(this,oldChild);
	},
	appendChild:function(newChild){
		return this.insertBefore(newChild,null);
	},
	hasChildNodes:function(){
		return this.firstChild != null;
	},
	cloneNode:function(deep){
		return cloneNode(this.ownerDocument||this,this,deep);
	},
	// Modified in DOM Level 2:
	normalize:function(){
		// Iterative traversal via walkDOM to avoid stack overflow on deeply nested trees
		// (GHSA-2v35-w6hq-6mfw). walkDOM reads lastChild/previousSibling after enter returns,
		// so it descends into the children that survive the merge, which is what the
		// recursive child.normalize() did.
		walkDOM(this, null, {
			enter:function(node){
				// Merge adjacent text children of node before walkDOM schedules them.
				var child = node.firstChild;
				while(child){
					var next = child.nextSibling;
					if(next && next.nodeType == TEXT_NODE && child.nodeType == TEXT_NODE){
						node.removeChild(next);
						child.appendData(next.data);
					}else{
						child = next;
					}
				}
				return true; // descend into surviving children
			}
		});
	},
  	// Introduced in DOM Level 2:
	isSupported:function(feature, version){
		return this.ownerDocument.implementation.hasFeature(feature,version);
	},
    // Introduced in DOM Level 2:
    hasAttributes:function(){
    	return this.attributes.length>0;
    },
    lookupPrefix:function(namespaceURI){
    	var el = this;
    	while(el){
    		var map = el._nsMap;
    		//console.dir(map)
    		if(map){
    			for(var n in map){
						if (Object.prototype.hasOwnProperty.call(map, n) && map[n] === namespaceURI) {
							return n;
						}
    			}
    		}
    		el = el.nodeType == ATTRIBUTE_NODE?el.ownerDocument : el.parentNode;
    	}
    	return null;
    },
    // Introduced in DOM Level 3:
    lookupNamespaceURI:function(prefix){
    	var el = this;
    	while(el){
    		var map = el._nsMap;
    		//console.dir(map)
    		if(map){
    			if(Object.prototype.hasOwnProperty.call(map, prefix)){
    				return map[prefix] ;
    			}
    		}
    		el = el.nodeType == ATTRIBUTE_NODE?el.ownerDocument : el.parentNode;
    	}
    	return null;
    },
    // Introduced in DOM Level 3:
    isDefaultNamespace:function(namespaceURI){
    	var prefix = this.lookupPrefix(namespaceURI);
    	return prefix == null;
    }
};


function _xmlEncoder(c){
	return c == '<' && '&lt;' ||
         c == '>' && '&gt;' ||
         c == '&' && '&amp;' ||
         c == '"' && '&quot;' ||
         '&#'+c.charCodeAt()+';'
}


copy(NodeType,Node);
copy(NodeType,Node.prototype);

/**
 * @param callback return true for continue,false for break
 * @return boolean true: break visit;
 */
function _visitNode(node,callback){
	// Iterative traversal via walkDOM to avoid stack overflow on deeply nested trees
	// (GHSA-2v35-w6hq-6mfw).
	return walkDOM(node, null, {
		enter: function(n){
			return callback(n) ? walkDOM.STOP : true;
		}
	}) === walkDOM.STOP;
}

/**
 * Depth-first pre/post-order DOM tree walker.
 *
 * Visits every node in the subtree rooted at `node`. For each node:
 *
 * 1. Calls `callbacks.enter(node, context)` before descending into the node's children. The
 * return value becomes the `context` passed to each child's `enter` call and to the matching
 * `exit` call.
 * 2. If `enter` returns `null` or `undefined`, the node's children are skipped;
 * sibling traversal continues normally.
 * 3. If `enter` returns `walkDOM.STOP`, the entire traversal is aborted immediately — no
 * further `enter` or `exit` calls are made.
 * 4. `lastChild` and `previousSibling` are read **after** `enter` returns, so `enter` may
 * safely modify the node's own child list before the walker descends. Modifying siblings of
 * the current node or any other part of the tree produces unpredictable results: nodes already
 * queued on the stack are visited regardless of DOM changes, and newly inserted nodes outside
 * the current child list are never visited.
 * 5. Calls `callbacks.exit(node, context)` (if provided) after all of a node's children have
 * been visited, passing the same `context` that `enter`
 * returned for that node.
 *
 * This implementation uses an explicit stack and does not recurse — it is safe on arbitrarily
 * deep trees.
 *
 * @param {Node} node
 * Root of the subtree to walk.
 * @param {*} context
 * Initial context value passed to the root node's `enter`.
 * @param {{ enter: function(Node, *): *, exit?: function(Node, *): void }} callbacks
 * @returns {void | walkDOM.STOP}
 * @see https://github.com/xmldom/xmldom/security/advisories/GHSA-2v35-w6hq-6mfw
 */
function walkDOM(node, context, callbacks) {
	// Each stack frame is {node, context, phase}:
	//   walkDOM.ENTER — call enter, then push children
	//   walkDOM.EXIT  — call exit
	var stack = [{ node: node, context: context, phase: walkDOM.ENTER }];
	while (stack.length > 0) {
		var frame = stack.pop();
		if (frame.phase === walkDOM.ENTER) {
			var childContext = callbacks.enter(frame.node, frame.context);
			if (childContext === walkDOM.STOP) {
				return walkDOM.STOP;
			}
			// Push exit frame before children so it fires after all children are processed (Last In First Out)
			stack.push({ node: frame.node, context: childContext, phase: walkDOM.EXIT });
			if (childContext === null || childContext === undefined) {
				continue; // skip children
			}
			// lastChild is read after enter returns, so enter may modify the child list.
			var child = frame.node.lastChild;
			// Traverse from lastChild backwards so that pushing onto the stack
			// naturally yields firstChild on top (processed first).
			while (child) {
				stack.push({ node: child, context: childContext, phase: walkDOM.ENTER });
				child = child.previousSibling;
			}
		} else {
			// frame.phase === walkDOM.EXIT
			if (callbacks.exit) {
				callbacks.exit(frame.node, frame.context);
			}
		}
	}
}

/**
 * Sentinel value returned from a `walkDOM` `enter` callback to abort the entire traversal
 * immediately.
 * A unique plain object is used, since `Symbol` is not available in every supported runtime.
 *
 * @type {Object}
 */
walkDOM.STOP = {};
/**
 * Phase constant for a stack frame that has not yet been visited.
 * The `enter` callback is called and children are scheduled.
 *
 * @type {number}
 */
walkDOM.ENTER = 0;
/**
 * Phase constant for a stack frame whose subtree has been fully visited.
 * The `exit` callback is called.
 *
 * @type {number}
 */
walkDOM.EXIT = 1;



function Document(){
	this.ownerDocument = this;
}
function _onAddAttribute(doc,el,newAttr){
	doc && doc._inc++;
	var ns = newAttr.namespaceURI ;
	if(ns == 'http://www.w3.org/2000/xmlns/'){
		//update namespace
		el._nsMap[newAttr.prefix?newAttr.localName:''] = newAttr.value
	}
}
function _onRemoveAttribute(doc,el,newAttr,remove){
	doc && doc._inc++;
	var ns = newAttr.namespaceURI ;
	if(ns == 'http://www.w3.org/2000/xmlns/'){
		//update namespace
		delete el._nsMap[newAttr.prefix?newAttr.localName:'']
	}
}
function _onUpdateChild(doc,el,newChild){
	if(doc && doc._inc){
		doc._inc++;
		//update childNodes
		var cs = el.childNodes;
		if(newChild){
			cs[cs.length++] = newChild;
		}else{
			//console.log(1)
			var child = el.firstChild;
			var i = 0;
			while(child){
				cs[i++] = child;
				child =child.nextSibling;
			}
			cs.length = i;
			delete cs[cs.length];
		}
	}
}

/**
 * attributes;
 * children;
 * 
 * writeable properties:
 * nodeValue,Attr:value,CharacterData:data
 * prefix
 */
function _removeChild(parentNode,child){
	var previous = child.previousSibling;
	var next = child.nextSibling;
	if(previous){
		previous.nextSibling = next;
	}else{
		parentNode.firstChild = next
	}
	if(next){
		next.previousSibling = previous;
	}else{
		parentNode.lastChild = previous;
	}
	child.parentNode = null;
	child.previousSibling = null;
	child.nextSibling = null;
	_onUpdateChild(parentNode.ownerDocument,parentNode);
	return child;
}

/**
 * Returns `true` if `node` can be a parent for insertion.
 * @param {Node} node
 * @returns {boolean}
 */
function hasValidParentNodeType(node) {
	return (
		node &&
		(node.nodeType === Node.DOCUMENT_NODE || node.nodeType === Node.DOCUMENT_FRAGMENT_NODE || node.nodeType === Node.ELEMENT_NODE)
	);
}

/**
 * Returns `true` if `node` can be inserted according to it's `nodeType`.
 * @param {Node} node
 * @returns {boolean}
 */
function hasInsertableNodeType(node) {
	return (
		node &&
		(isElementNode(node) ||
			isTextNode(node) ||
			isDocTypeNode(node) ||
			node.nodeType === Node.DOCUMENT_FRAGMENT_NODE ||
			node.nodeType === Node.COMMENT_NODE ||
			// CDATASection is CharacterData too, it was always insertable into elements and fragments
			node.nodeType === Node.CDATA_SECTION_NODE ||
			node.nodeType === Node.PROCESSING_INSTRUCTION_NODE)
	);
}

/**
 * Returns true if `node` is a DOCTYPE node
 * @param {Node} node
 * @returns {boolean}
 */
function isDocTypeNode(node) {
	return node && node.nodeType === Node.DOCUMENT_TYPE_NODE;
}

/**
 * Returns true if the node is an element
 * @param {Node} node
 * @returns {boolean}
 */
function isElementNode(node) {
	return node && node.nodeType === Node.ELEMENT_NODE;
}
/**
 * Returns true if `node` is a text node
 * @param {Node} node
 * @returns {boolean}
 */
function isTextNode(node) {
	return node && node.nodeType === Node.TEXT_NODE;
}

/**
 * Check if en element node can be inserted before `child`, or at the end if child is falsy,
 * according to the presence and position of a doctype node on the same level.
 *
 * @param {Document} doc The document node
 * @param {Node} child the node that would become the nextSibling if the element would be inserted
 * @returns {boolean} `true` if an element can be inserted before child
 * @private
 * https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
 */
function isElementInsertionPossible(doc, child) {
	var parentChildNodes = doc.childNodes || [];
	if (find(parentChildNodes, isElementNode) || isDocTypeNode(child)) {
		return false;
	}
	var docTypeNode = find(parentChildNodes, isDocTypeNode);
	return !(child && docTypeNode && parentChildNodes.indexOf(docTypeNode) > parentChildNodes.indexOf(child));
}

/**
 * Check if en element node can be inserted before `child`, or at the end if child is falsy,
 * according to the presence and position of a doctype node on the same level.
 *
 * @param {Node} doc The document node
 * @param {Node} child the node that would become the nextSibling if the element would be inserted
 * @returns {boolean} `true` if an element can be inserted before child
 * @private
 * https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
 */
function isElementReplacementPossible(doc, child) {
	var parentChildNodes = doc.childNodes || [];

	function hasElementChildThatIsNotChild(node) {
		return isElementNode(node) && node !== child;
	}

	if (find(parentChildNodes, hasElementChildThatIsNotChild)) {
		return false;
	}
	var docTypeNode = find(parentChildNodes, isDocTypeNode);
	return !(child && docTypeNode && parentChildNodes.indexOf(docTypeNode) > parentChildNodes.indexOf(child));
}

/**
 * @private
 * Steps 1-5 of the checks before inserting and before replacing a child are the same.
 *
 * @param {Node} parent the parent node to insert `node` into
 * @param {Node} node the node to insert
 * @param {Node=} child the node that should become the `nextSibling` of `node`
 * @returns {Node}
 * @throws DOMException for several node combinations that would create a DOM that is not well-formed.
 * @throws DOMException if `child` is provided but is not a child of `parent`.
 * @see https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
 * @see https://dom.spec.whatwg.org/#concept-node-replace
 */
function assertPreInsertionValidity1to5(parent, node, child) {
	// 1. If `parent` is not a Document, DocumentFragment, or Element node, then throw a "HierarchyRequestError" DOMException.
	if (!hasValidParentNodeType(parent)) {
		throw new DOMException(HIERARCHY_REQUEST_ERR, 'Unexpected parent node type ' + parent.nodeType);
	}
	// 2. If `node` is a host-including inclusive ancestor of `parent`, then throw a "HierarchyRequestError" DOMException.
	// not implemented!
	// 3. If `child` is non-null and its parent is not `parent`, then throw a "NotFoundError" DOMException.
	if (child && child.parentNode !== parent) {
		throw new DOMException(NOT_FOUND_ERR, 'child not in parent');
	}
	if (
		// 4. If `node` is not a DocumentFragment, DocumentType, Element, or CharacterData node, then throw a "HierarchyRequestError" DOMException.
		!hasInsertableNodeType(node) ||
		// 5. If either `node` is a Text node and `parent` is a document,
		// the sax parser currently adds top level text nodes, this will be fixed in 0.9.0
		// || (node.nodeType === Node.TEXT_NODE && parent.nodeType === Node.DOCUMENT_NODE)
		// or `node` is a doctype and `parent` is not a document, then throw a "HierarchyRequestError" DOMException.
		(isDocTypeNode(node) && parent.nodeType !== Node.DOCUMENT_NODE)
	) {
		throw new DOMException(
			HIERARCHY_REQUEST_ERR,
			'Unexpected node type ' + node.nodeType + ' for parent node type ' + parent.nodeType
		);
	}
}

/**
 * @private
 * Step 6 of the checks before inserting and before replacing a child are different.
 *
 * @param {Document} parent the parent node to insert `node` into
 * @param {Node} node the node to insert
 * @param {Node | undefined} child the node that should become the `nextSibling` of `node`
 * @returns {Node}
 * @throws DOMException for several node combinations that would create a DOM that is not well-formed.
 * @throws DOMException if `child` is provided but is not a child of `parent`.
 * @see https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
 * @see https://dom.spec.whatwg.org/#concept-node-replace
 */
function assertPreInsertionValidityInDocument(parent, node, child) {
	var parentChildNodes = parent.childNodes || [];
	var nodeChildNodes = node.childNodes || [];

	// DocumentFragment
	if (node.nodeType === Node.DOCUMENT_FRAGMENT_NODE) {
		var nodeChildElements = nodeChildNodes.filter(isElementNode);
		// If node has more than one element child or has a Text node child.
		if (nodeChildElements.length > 1 || find(nodeChildNodes, isTextNode)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'More than one element or text in fragment');
		}
		// Otherwise, if `node` has one element child and either `parent` has an element child,
		// `child` is a doctype, or `child` is non-null and a doctype is following `child`.
		if (nodeChildElements.length === 1 && !isElementInsertionPossible(parent, child)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Element in fragment can not be inserted before doctype');
		}
	}
	// Element
	if (isElementNode(node)) {
		// `parent` has an element child, `child` is a doctype,
		// or `child` is non-null and a doctype is following `child`.
		if (!isElementInsertionPossible(parent, child)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Only one element can be added and only after doctype');
		}
	}
	// DocumentType
	if (isDocTypeNode(node)) {
		// `parent` has a doctype child,
		if (find(parentChildNodes, isDocTypeNode)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Only one doctype is allowed');
		}
		var parentElementChild = find(parentChildNodes, isElementNode);
		// `child` is non-null and an element is preceding `child`,
		if (child && parentElementChild && parentChildNodes.indexOf(parentElementChild) < parentChildNodes.indexOf(child)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Doctype can only be inserted before an element');
		}
		// or `child` is null and `parent` has an element child.
		if (!child && parentElementChild) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Doctype can not be appended since element is present');
		}
	}
}

/**
 * @private
 * Step 6 of the checks before inserting and before replacing a child are different.
 *
 * @param {Document} parent the parent node to insert `node` into
 * @param {Node} node the node to insert
 * @param {Node | undefined} child the node that should become the `nextSibling` of `node`
 * @returns {Node}
 * @throws DOMException for several node combinations that would create a DOM that is not well-formed.
 * @throws DOMException if `child` is provided but is not a child of `parent`.
 * @see https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
 * @see https://dom.spec.whatwg.org/#concept-node-replace
 */
function assertPreReplacementValidityInDocument(parent, node, child) {
	var parentChildNodes = parent.childNodes || [];
	var nodeChildNodes = node.childNodes || [];

	function hasDoctypeChildThatIsNotChild(node) {
		return isDocTypeNode(node) && node !== child;
	}

	// DocumentFragment
	if (node.nodeType === Node.DOCUMENT_FRAGMENT_NODE) {
		var nodeChildElements = nodeChildNodes.filter(isElementNode);
		// If `node` has more than one element child or has a Text node child.
		if (nodeChildElements.length > 1 || find(nodeChildNodes, isTextNode)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'More than one element or text in fragment');
		}
		// Otherwise, if `node` has one element child and either `parent` has an element child that is not `child` or a doctype is following `child`.
		if (nodeChildElements.length === 1 && !isElementReplacementPossible(parent, child)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Element in fragment can not be inserted before doctype');
		}
	}
	// Element
	if (isElementNode(node)) {
		// `parent` has an element child that is not `child` or a doctype is following `child`.
		if (!isElementReplacementPossible(parent, child)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Only one element can be added and only after doctype');
		}
	}
	// DocumentType
	if (isDocTypeNode(node)) {
		// `parent` has a doctype child that is not `child`,
		if (find(parentChildNodes, hasDoctypeChildThatIsNotChild)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Only one doctype is allowed');
		}
		var parentElementChild = find(parentChildNodes, isElementNode);
		// or an element is preceding `child`.
		if (child && parentElementChild && parentChildNodes.indexOf(parentElementChild) < parentChildNodes.indexOf(child)) {
			throw new DOMException(HIERARCHY_REQUEST_ERR, 'Doctype can only be inserted before an element');
		}
	}
}

/**
 * @private
 * @param {Node} parent the parent node to insert `node` into
 * @param {Node} node the node to insert
 * @param {Node=} child the node that should become the `nextSibling` of `node`
 * @returns {Node}
 * @throws DOMException for several node combinations that would create a DOM that is not well-formed.
 * @throws DOMException if `child` is provided but is not a child of `parent`.
 * @see https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity
 */
function _insertBefore(parent, node, child, _inDocumentAssertion) {
	// To ensure pre-insertion validity of a node into a parent before a child, run these steps:
	assertPreInsertionValidity1to5(parent, node, child);

	// If parent is a document, and any of the statements below, switched on the interface node implements,
	// are true, then throw a "HierarchyRequestError" DOMException.
	if (parent.nodeType === Node.DOCUMENT_NODE) {
		(_inDocumentAssertion || assertPreInsertionValidityInDocument)(parent, node, child);
	}

	var cp = node.parentNode;
	if(cp){
		cp.removeChild(node);//remove and update
	}
	if(node.nodeType === DOCUMENT_FRAGMENT_NODE){
		var newFirst = node.firstChild;
		if (newFirst == null) {
			return node;
		}
		var newLast = node.lastChild;
	}else{
		newFirst = newLast = node;
	}
	var pre = child ? child.previousSibling : parent.lastChild;

	newFirst.previousSibling = pre;
	newLast.nextSibling = child;


	if(pre){
		pre.nextSibling = newFirst;
	}else{
		parent.firstChild = newFirst;
	}
	if(child == null){
		parent.lastChild = newLast;
	}else{
		child.previousSibling = newLast;
	}
	do{
		newFirst.parentNode = parent;
	}while(newFirst !== newLast && (newFirst= newFirst.nextSibling))
	_onUpdateChild(parent.ownerDocument||parent, parent);
	//console.log(parent.lastChild.nextSibling == null)
	if (node.nodeType == DOCUMENT_FRAGMENT_NODE) {
		node.firstChild = node.lastChild = null;
	}
	return node;
}
function _appendSingleChild(parentNode,newChild){
	var cp = newChild.parentNode;
	if(cp){
		var pre = parentNode.lastChild;
		cp.removeChild(newChild);//remove and update
		var pre = parentNode.lastChild;
	}
	var pre = parentNode.lastChild;
	newChild.parentNode = parentNode;
	newChild.previousSibling = pre;
	newChild.nextSibling = null;
	if(pre){
		pre.nextSibling = newChild;
	}else{
		parentNode.firstChild = newChild;
	}
	parentNode.lastChild = newChild;
	_onUpdateChild(parentNode.ownerDocument,parentNode,newChild);
	return newChild;
	//console.log("__aa",parentNode.lastChild.nextSibling == null)
}
Document.prototype = {
	//implementation : null,
	nodeName :  '#document',
	nodeType :  DOCUMENT_NODE,
	doctype :  null,
	documentElement :  null,
	_inc : 1,
	
	insertBefore :  function(newChild, refChild){//raises 
		if(newChild.nodeType == DOCUMENT_FRAGMENT_NODE){
			var child = newChild.firstChild;
			while(child){
				var next = child.nextSibling;
				this.insertBefore(child,refChild);
				child = next;
			}
			return newChild;
		}
		_insertBefore(this, newChild, refChild);
		newChild.ownerDocument = this;
		if(this.documentElement == null && newChild.nodeType == ELEMENT_NODE){
			this.documentElement = newChild;
		}

		return newChild;
	},
	removeChild :  function(oldChild){
		if(this.documentElement == oldChild){
			this.documentElement = null;
		}
		return _removeChild(this,oldChild);
	},
	replaceChild: function (newChild, oldChild) {
		//raises
		_insertBefore(this, newChild, oldChild, assertPreReplacementValidityInDocument);
		newChild.ownerDocument = this;
		if (oldChild) {
			this.removeChild(oldChild);
		}
		if (isElementNode(newChild)) {
			this.documentElement = newChild;
		}
	},
	// Introduced in DOM Level 2:
	importNode : function(importedNode,deep){
		return importNode(this,importedNode,deep);
	},
	// Introduced in DOM Level 2:
	getElementById :	function(id){
		var rtv = null;
		_visitNode(this.documentElement,function(node){
			if(node.nodeType == ELEMENT_NODE){
				if(node.getAttribute('id') == id){
					rtv = node;
					return true;
				}
			}
		})
		return rtv;
	},
	
	//document factory method:
	createElement :	function(tagName){
		var node = new Element();
		node.ownerDocument = this;
		node.nodeName = tagName;
		node.tagName = tagName;
		node.childNodes = new NodeList();
		var attrs	= node.attributes = new NamedNodeMap();
		attrs._ownerElement = node;
		return node;
	},
	createDocumentFragment :	function(){
		var node = new DocumentFragment();
		node.ownerDocument = this;
		node.childNodes = new NodeList();
		return node;
	},
	createTextNode :	function(data){
		var node = new Text();
		node.ownerDocument = this;
		node.appendData(data)
		return node;
	},
	/**
	 * @param {string} data
	 * @returns {Comment}
	 * @see https://dom.spec.whatwg.org/#dom-document-createcomment
	 * @see https://www.w3.org/TR/xml/#NT-Comment XML 1.0 production [15]
	 * @see https://www.w3.org/TR/DOM-Parsing/#dfn-concept-serialize-xml §3.2.1.3
	 *
	 *      Note: no validation is performed at creation time. When the resulting document is
	 *      serialized with `requireWellFormed: true`, the serializer throws `InvalidStateError`
	 *      if the comment data contains `--` anywhere, ends with `-`, or contains characters
	 *      outside the XML Char production (W3C DOM Parsing §3.2.1.3). Without that option the
	 *      data is emitted verbatim.
	 */
	createComment :	function(data){
		var node = new Comment();
		node.ownerDocument = this;
		node.appendData(data)
		return node;
	},
	/**
	 * Returns a new CDATASection node whose data is `data`.
	 *
	 * __This implementation differs from the specification:__
	 * - calling this method on an HTML document does not throw `NotSupportedError`.
	 *
	 * @param {string} data
	 * @returns {CDATASection}
	 * @throws DOMException with code `INVALID_CHARACTER_ERR` if `data` contains `"]]>"`.
	 * @see https://developer.mozilla.org/en-US/docs/Web/API/Document/createCDATASection
	 * @see https://dom.spec.whatwg.org/#dom-document-createcdatasection
	 */
	createCDATASection :	function(data){
		if (data.indexOf(']]>') !== -1) {
			throw new DOMException(INVALID_CHARACTER_ERR, 'data contains "]]>"');
		}
		var node = new CDATASection();
		node.ownerDocument = this;
		node.appendData(data)
		return node;
	},
	/**
	 * Returns a ProcessingInstruction node whose target is target and data is data.
	 *
	 * __This implementation differs from the specification:__
	 * - it does not do any input validation on the arguments and doesn't throw
	 * "InvalidCharacterError".
	 *
	 * Note: When the resulting document is serialized with `requireWellFormed: true`, the
	 * serializer throws `InvalidStateError` if `.target` contains `:`, is an ASCII
	 * case-insensitive match for `"xml"` or is not a valid XML `Name`, or if `.data` contains
	 * `?>` or characters outside the XML Char production (W3C DOM Parsing §3.2.1.7). Without
	 * that option the data is emitted verbatim.
	 *
	 * @param {string} target
	 * @param {string} data
	 * @returns {ProcessingInstruction}
	 * @see https://developer.mozilla.org/docs/Web/API/Document/createProcessingInstruction
	 * @see https://dom.spec.whatwg.org/#dom-document-createprocessinginstruction
	 * @see https://www.w3.org/TR/DOM-Parsing/#dfn-concept-serialize-xml §3.2.1.7
	 */
	createProcessingInstruction :	function(target,data){
		var node = new ProcessingInstruction();
		node.ownerDocument = this;
		node.tagName = node.target = target;
		node.nodeValue= node.data = data;
		return node;
	},
	createAttribute :	function(name){
		var node = new Attr();
		node.ownerDocument	= this;
		node.name = name;
		node.nodeName	= name;
		node.localName = name;
		node.specified = true;
		return node;
	},
	/**
	 * Creates an EntityReference object, serialized as `&name;`.
	 *
	 * The `name` is validated against the XML `Name` production at creation time; an invalid name
	 * throws a `DOMException` with code `INVALID_CHARACTER_ERR`. When the resulting node is
	 * serialized with `requireWellFormed: true`, the serializer re-validates `nodeName` and throws
	 * a `DOMException` with code `INVALID_STATE_ERR` if a later `nodeName` mutation made it invalid;
	 * without that option the name is emitted verbatim.
	 *
	 * Note: xmldom does not expand entities — the parser resolves entity references inline and never
	 * constructs `EntityReference` nodes, so this method is the only producer.
	 *
	 * @param {string} name The name of the entity to reference.
	 * @returns {EntityReference}
	 * @throws {DOMException} With code `INVALID_CHARACTER_ERR` when `name` is not a valid XML `Name`.
	 * @see https://www.w3.org/TR/DOM-Level-3-Core/core.html#ID-392B75AE
	 */
	createEntityReference :	function(name){
		if (!tagNamePattern.test(name)) {
			throw new DOMException(INVALID_CHARACTER_ERR, 'not a valid xml name "' + name + '"');
		}
		var node = new EntityReference();
		node.ownerDocument	= this;
		node.nodeName	= name;
		return node;
	},
	// Introduced in DOM Level 2:
	createElementNS :	function(namespaceURI,qualifiedName){
		var node = new Element();
		var pl = qualifiedName.split(':');
		var attrs	= node.attributes = new NamedNodeMap();
		node.childNodes = new NodeList();
		node.ownerDocument = this;
		node.nodeName = qualifiedName;
		node.tagName = qualifiedName;
		node.namespaceURI = namespaceURI;
		if(pl.length == 2){
			node.prefix = pl[0];
			node.localName = pl[1];
		}else{
			//el.prefix = null;
			node.localName = qualifiedName;
		}
		attrs._ownerElement = node;
		return node;
	},
	// Introduced in DOM Level 2:
	createAttributeNS :	function(namespaceURI,qualifiedName){
		var node = new Attr();
		var pl = qualifiedName.split(':');
		node.ownerDocument = this;
		node.nodeName = qualifiedName;
		node.name = qualifiedName;
		node.namespaceURI = namespaceURI;
		node.specified = true;
		if(pl.length == 2){
			node.prefix = pl[0];
			node.localName = pl[1];
		}else{
			//el.prefix = null;
			node.localName = qualifiedName;
		}
		return node;
	}
};
_extends(Document,Node);


function Element() {
	this._nsMap = {};
};
Element.prototype = {
	nodeType : ELEMENT_NODE,
	hasAttribute : function(name){
		return this.getAttributeNode(name)!=null;
	},
	getAttribute : function(name){
		var attr = this.getAttributeNode(name);
		return attr && attr.value || '';
	},
	getAttributeNode : function(name){
		return this.attributes.getNamedItem(name);
	},
	setAttribute : function(name, value){
		var attr = this.ownerDocument.createAttribute(name);
		attr.value = attr.nodeValue = "" + value;
		this.setAttributeNode(attr)
	},
	removeAttribute : function(name){
		var attr = this.getAttributeNode(name)
		attr && this.removeAttributeNode(attr);
	},
	
	//four real opeartion method
	appendChild:function(newChild){
		if(newChild.nodeType === DOCUMENT_FRAGMENT_NODE){
			return this.insertBefore(newChild,null);
		}else{
			return _appendSingleChild(this,newChild);
		}
	},
	setAttributeNode : function(newAttr){
		return this.attributes.setNamedItem(newAttr);
	},
	setAttributeNodeNS : function(newAttr){
		return this.attributes.setNamedItemNS(newAttr);
	},
	removeAttributeNode : function(oldAttr){
		//console.log(this == oldAttr.ownerElement)
		return this.attributes.removeNamedItem(oldAttr.nodeName);
	},
	//get real attribute name,and remove it by removeAttributeNode
	removeAttributeNS : function(namespaceURI, localName){
		var old = this.getAttributeNodeNS(namespaceURI, localName);
		old && this.removeAttributeNode(old);
	},
	
	hasAttributeNS : function(namespaceURI, localName){
		return this.getAttributeNodeNS(namespaceURI, localName)!=null;
	},
	getAttributeNS : function(namespaceURI, localName){
		var attr = this.getAttributeNodeNS(namespaceURI, localName);
		return attr && attr.value || '';
	},
	setAttributeNS : function(namespaceURI, qualifiedName, value){
		var attr = this.ownerDocument.createAttributeNS(namespaceURI, qualifiedName);
		attr.value = attr.nodeValue = "" + value;
		this.setAttributeNode(attr)
	},
	getAttributeNodeNS : function(namespaceURI, localName){
		return this.attributes.getNamedItemNS(namespaceURI, localName);
	},
	
	getElementsByTagName : function(tagName){
		return new LiveNodeList(this,function(base){
			var ls = [];
			_visitNode(base,function(node){
				if(node !== base && node.nodeType == ELEMENT_NODE && (tagName === '*' || node.tagName == tagName)){
					ls.push(node);
				}
			});
			return ls;
		});
	},
	getElementsByTagNameNS : function(namespaceURI, localName){
		return new LiveNodeList(this,function(base){
			var ls = [];
			_visitNode(base,function(node){
				if(node !== base && node.nodeType === ELEMENT_NODE && (namespaceURI === '*' || node.namespaceURI === namespaceURI) && (localName === '*' || node.localName == localName)){
					ls.push(node);
				}
			});
			return ls;
			
		});
	}
};
Document.prototype.getElementsByTagName = Element.prototype.getElementsByTagName;
Document.prototype.getElementsByTagNameNS = Element.prototype.getElementsByTagNameNS;


_extends(Element,Node);
function Attr() {
};
Attr.prototype.nodeType = ATTRIBUTE_NODE;
_extends(Attr,Node);


function CharacterData() {
};
CharacterData.prototype = {
	data : '',
	substringData : function(offset, count) {
		return this.data.substring(offset, offset+count);
	},
	appendData: function(text) {
		text = this.data+text;
		this.nodeValue = this.data = text;
		this.length = text.length;
	},
	insertData: function(offset,text) {
		this.replaceData(offset,0,text);
	
	},
	appendChild:function(newChild){
		throw new Error(ExceptionMessage[HIERARCHY_REQUEST_ERR])
	},
	deleteData: function(offset, count) {
		this.replaceData(offset,count,"");
	},
	replaceData: function(offset, count, text) {
		var start = this.data.substring(0,offset);
		var end = this.data.substring(offset+count);
		text = start + text + end;
		this.nodeValue = this.data = text;
		this.length = text.length;
	}
}
_extends(CharacterData,Node);
function Text() {
};
Text.prototype = {
	nodeName : "#text",
	nodeType : TEXT_NODE,
	splitText : function(offset) {
		var text = this.data;
		var newText = text.substring(offset);
		text = text.substring(0, offset);
		this.data = this.nodeValue = text;
		this.length = text.length;
		var newNode = this.ownerDocument.createTextNode(newText);
		if(this.parentNode){
			this.parentNode.insertBefore(newNode, this.nextSibling);
		}
		return newNode;
	}
}
_extends(Text,CharacterData);
function Comment() {
};
Comment.prototype = {
	nodeName : "#comment",
	nodeType : COMMENT_NODE
}
_extends(Comment,CharacterData);

function CDATASection() {
};
CDATASection.prototype = {
	nodeName : "#cdata-section",
	nodeType : CDATA_SECTION_NODE
}
_extends(CDATASection,CharacterData);


/**
 * Represents a DocumentType node (the `<!DOCTYPE ...>` declaration).
 *
 * `name`, `publicId`, `systemId`, and `internalSubset` are plain own-property assignments.
 * xmldom does not enforce the `readonly` constraint declared by the WHATWG DOM spec —
 * direct property writes succeed silently. Values are serialized verbatim when
 * `requireWellFormed` is false (the default). When the serializer is invoked with
 * `requireWellFormed: true` (via the 4th-parameter options object), it validates each
 * field — including `name`, which is checked against the XML `Name` production — and throws
 * `DOMException` with code `INVALID_STATE_ERR` on invalid values.
 *
 * @class
 * @see https://developer.mozilla.org/docs/Web/API/DocumentType MDN
 */
function DocumentType() {
};
DocumentType.prototype.nodeType = DOCUMENT_TYPE_NODE;
_extends(DocumentType,Node);

function Notation() {
};
Notation.prototype.nodeType = NOTATION_NODE;
_extends(Notation,Node);

function Entity() {
};
Entity.prototype.nodeType = ENTITY_NODE;
_extends(Entity,Node);

/**
 * Represents an EntityReference node, serialized as `&nodeName;`.
 *
 * `nodeName` is the referenced entity's name, stored verbatim. When serialized with
 * `requireWellFormed: true`, the serializer validates `nodeName` against the XML `Name` production
 * and throws a `DOMException` with code `INVALID_STATE_ERR` if it does not match; without that
 * option the name is emitted verbatim between `&` and `;`.
 *
 * Note: xmldom does not expand entities — the parser resolves entity references inline and never
 * constructs `EntityReference` nodes, so the only producer is `Document.createEntityReference`.
 *
 * @class
 * @see https://www.w3.org/TR/xml/#NT-Name
 */
function EntityReference() {
};
EntityReference.prototype.nodeType = ENTITY_REFERENCE_NODE;
_extends(EntityReference,Node);

function DocumentFragment() {
};
DocumentFragment.prototype.nodeName =	"#document-fragment";
DocumentFragment.prototype.nodeType =	DOCUMENT_FRAGMENT_NODE;
_extends(DocumentFragment,Node);


function ProcessingInstruction() {
}
ProcessingInstruction.prototype.nodeType = PROCESSING_INSTRUCTION_NODE;
_extends(ProcessingInstruction,Node);
function XMLSerializer(){}
/**
 * Returns the result of serializing `node` to XML.
 *
 * When `options.requireWellFormed` is `true`, the serializer throws for content that would
 * produce ill-formed XML.
 *
 * __This implementation differs from the specification:__
 * - CDATASection nodes whose data contains `]]>` are serialized by splitting the section
 *   at each `]]>` occurrence (following W3C DOM Level 3 Core `split-cdata-sections`
 *   default behaviour) unless `requireWellFormed` is `true`.
 * - W3C DOM Parsing §3.2.1.1 requires well-formedness checks on Element `localName`s,
 *   prefixes, and attribute serialization when `requireWellFormed` is `true`. This release
 *   only checks that the qualified names of elements and attributes (synthesized `xmlns`
 *   declarations included) are valid XML QNames.
 *
 * @param {Node} node
 * @param {boolean} [isHtml]
 * @param {function} [nodeFilter]
 * @param {Object} [options]
 * @param {boolean} [options.requireWellFormed=false]
 * When `true`, throws for content that would produce ill-formed XML.
 * @returns {string}
 * @throws {DOMException}
 * With code `INVALID_STATE_ERR` when `requireWellFormed` is `true` and any of the following
 * conditions hold: an Element's qualified name (including any namespace prefix) is not a valid
 * XML QName; an attribute's qualified name (including a synthesized `xmlns:` namespace
 * declaration) is not a valid XML QName; CDATASection data contains `"]]>"`; a Comment node's
 * data contains `--` anywhere, ends with `-`, or contains characters outside the XML Char production; a
 * DocumentType's `name` is not a valid XML `Name` (XML 1.0 production [5]); a DocumentType's
 * `publicId` is non-empty and does not match the XML `PubidLiteral` production; a
 * DocumentType's `systemId` is non-empty and does not match the XML `SystemLiteral`
 * production; a DocumentType's `internalSubset` contains `"]>"`; a ProcessingInstruction's
 * `target` contains `:`, is an ASCII case-insensitive match for `"xml"` or is not a valid XML
 * `Name`; a ProcessingInstruction's `data` contains `"?>"` or characters outside the XML Char
 * production; an EntityReference's `nodeName` is not a valid XML `Name` (XML 1.0 production [5]).
 * Note: xmldom does not enforce `readonly` on DocumentType fields — direct property writes
 * succeed and are covered by the serializer-level checks above.
 * @see https://developer.mozilla.org/docs/Web/API/XMLSerializer/serializeToString
 * @see https://html.spec.whatwg.org/#dom-xmlserializer-serializetostring
 * @see https://github.com/w3c/DOM-Parsing/issues/84
 */
XMLSerializer.prototype.serializeToString = function(node,isHtml,nodeFilter,options){
	return nodeSerializeToString.call(node,isHtml,nodeFilter,options);
}
Node.prototype.toString = nodeSerializeToString;
function nodeSerializeToString(isHtml,nodeFilter,options){
	var requireWellFormed = options != null ? !!options.requireWellFormed : false;
	var buf = [];
	var refNode = this.nodeType == 9?this.documentElement:this;
	var prefix = refNode.prefix;
	var uri = refNode.namespaceURI;
	
	if(uri && prefix == null){
		//console.log(prefix)
		var prefix = refNode.lookupPrefix(uri);
		if(prefix == null){
			//isHTML = true;
			var visibleNamespaces=[
			{namespace:uri,prefix:null}
			//{namespace:uri,prefix:''}
			]
		}
	}
	serializeToString(this,buf,isHtml,nodeFilter,visibleNamespaces,requireWellFormed);
	//console.log('###',this.nodeType,uri,prefix,buf.join(''))
	return buf.join('');
}
function needNamespaceDefine(node,isHTML, visibleNamespaces) {
	var prefix = node.prefix||'';
	var uri = node.namespaceURI;
	if (!prefix && !uri){
		return false;
	}
	if (prefix === "xml" && uri === "http://www.w3.org/XML/1998/namespace" 
		|| uri == 'http://www.w3.org/2000/xmlns/'){
		return false;
	}
	
	var i = visibleNamespaces.length 
	//console.log('@@@@',node.tagName,prefix,uri,visibleNamespaces)
	while (i--) {
		var ns = visibleNamespaces[i];
		// get namespace prefix
		//console.log(node.nodeType,node.tagName,ns.prefix,prefix)
		if (ns.prefix == prefix){
			return ns.namespace != uri;
		}
	}
	//console.log(isHTML,uri,prefix=='')
	//if(isHTML && prefix ==null && uri == 'http://www.w3.org/1999/xhtml'){
	//	return false;
	//}
	//node.flag = '11111'
	//console.error(3,true,node.flag,node.prefix,node.namespaceURI)
	return true;
}
/**
 * Quotes the public or system identifier of a DOCTYPE, so that it is always serialized
 * as exactly one literal and its content can not end up as markup (e.g. an internal subset).
 * The identifier is delimited by '"', or by "'" when it contains '"'.
 * A literal can not contain its own delimiter, so when the identifier contains both quotes
 * every '"' is percent encoded (as in a URI).
 */
function _quoteDoctypeId(id){
	id = String(id);
	if(id.indexOf('"') < 0){
		return '"' + id + '"';
	}
	if(id.indexOf("'") < 0){
		return "'" + id + "'";
	}
	return '"' + id.replace(/"/g, '%22') + '"';
}
/**
 * Well-formed constraint: No < in Attribute Values
 * The replacement text of any entity referred to directly or indirectly in an attribute value must not contain a <.
 *
 * When `requireWellFormed` is `true`, `qualifiedName` has to be a valid XML QName, otherwise
 * a DOMException with code `INVALID_STATE_ERR` is thrown (the name is not validated when the
 * attribute is created, and it is emitted as is).
 * @see https://www.w3.org/TR/xml/#CleanAttrVals
 * @see https://www.w3.org/TR/xml/#NT-AttValue
 * @see https://w3c.github.io/DOM-Parsing/#serializing-an-element-s-attributes
 * @see https://github.com/xmldom/xmldom/security/advisories/GHSA-4w3w-2rp5-g8jm
 */
function addSerializedAttribute(buf, qualifiedName, value, requireWellFormed) {
	if (requireWellFormed && !tagNamePattern.test(qualifiedName)) {
		throw new DOMException(INVALID_STATE_ERR, 'The attribute name "' + qualifiedName + '" is not a valid XML QName');
	}
	// a prefix without a namespace URI (lenient parse, createElementNS(null,'p:x'))
	// serialized as xmlns:p="" before this escaping was added; keep that output
	value = value == null ? '' : String(value);
	buf.push(' ', qualifiedName, '="', value.replace(/[<&"]/g,_xmlEncoder), '"')
}

/**
 * Matches any character that is not a valid XML 1.0 Char.
 * `[2] Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]`
 * Characters above #xFFFF are UTF-16 surrogate pairs (there is no RegExp `u` flag in ES5),
 * so only unpaired surrogates are matched.
 * @see https://www.w3.org/TR/xml/#NT-Char
 */
var InvalidChar = /[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Full-string anchored matcher for the `requireWellFormed` DocumentType publicId check.
 * In this version `publicId` and `systemId` hold the identifier without its quotes and
 * `_quoteDoctypeId` adds them when serializing, so the checks apply to the unquoted content:
 * `publicId` must only contain `PubidChar`s (it is then serialized as a `PubidLiteral`), and
 * `systemId` must not contain both quote characters (it is then serialized as a `SystemLiteral`
 * without being altered).
 * The matcher is deliberately not multiline, so `^` and `$` only match at the start and end of
 * the whole value and a line terminator can not end a valid value early.
 * `[11] SystemLiteral ::= ('"' [^"]* '"') | ("'" [^']* "'")`
 * `[12] PubidLiteral ::= '"' PubidChar* '"' | "'" (PubidChar - "'")* "'"`
 * `[13] PubidChar ::= #x20 | #xD | #xA | [a-zA-Z0-9] | [-'()+,./:=?;!*#@$_%]`
 * @see https://www.w3.org/TR/xml/#NT-SystemLiteral
 * @see https://www.w3.org/TR/xml/#NT-PubidLiteral
 * @see https://w3c.github.io/DOM-Parsing/#xml-serializing-a-documenttype-node
 */
var PubidChars_match = /^[\x20\x0D\x0Aa-zA-Z0-9\-'()+,.\/:=?;!*#@$_%]*$/;

/**
 * The XML `Name` pattern the SAX parser uses for tag names (a copy of the one in sax.js),
 * used to validate the DocumentType name, the ProcessingInstruction target, the EntityReference
 * name and the qualified names of elements and attributes (synthesized `xmlns` declarations
 * included) when `requireWellFormed` is `true`, and the name passed to `createEntityReference`.
 * `[5] Name ::= NameStartChar (NameChar)*`
 * @see https://www.w3.org/TR/xml/#NT-Name
 * @see https://www.w3.org/TR/xml-names/#NT-QName
 */
var nameStartChar = /[A-Z_a-z\xC0-\xD6\xD8-\xF6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]///\u10000-\uEFFFF
var nameChar = new RegExp("[\\-\\.0-9"+nameStartChar.source.slice(1,-1)+"\\u00B7\\u0300-\\u036F\\u203F-\\u2040]");
var tagNamePattern = new RegExp('^'+nameStartChar.source+nameChar.source+'*(?:\:'+nameStartChar.source+nameChar.source+'*)?$');

function serializeToString(node,buf,isHTML,nodeFilter,visibleNamespaces,requireWellFormed){
	// Iterative traversal with an explicit stack to avoid stack overflow on deeply nested trees
	// (GHSA-2v35-w6hq-6mfw). Each frame carries the isHTML and visibleNamespaces values the
	// recursive call used to receive; a frame with `closeTag` writes the end tag of an element
	// once all of its children have been serialized.
	var stack = [{ node: node, isHTML: isHTML, visibleNamespaces: visibleNamespaces }];
	while(stack.length > 0){
		var frame = stack.pop();
		if('closeTag' in frame){
			buf.push('</',frame.closeTag,'>');
			continue;
		}
		node = frame.node;
		isHTML = frame.isHTML;
		visibleNamespaces = frame.visibleNamespaces;
		//if is cdata child node of a html script element
		if(frame.inScript && node.data){
			buf.push(node.data);
			continue;
		}
		if(nodeFilter){
			node = nodeFilter(node);
			if(node){
				if(typeof node == 'string'){
					buf.push(node);
					continue;
				}
			}else{
				continue;
			}
			//buf.sort.apply(attrs, attributeSorter);
		}
		switch(node.nodeType){
		case ELEMENT_NODE:
			if (!visibleNamespaces) visibleNamespaces = [];
			var startVisibleNamespaces = visibleNamespaces.length;
			var attrs = node.attributes;
			var len = attrs.length;
			var child = node.firstChild;
			var nodeName = node.tagName;

			isHTML =  (htmlns === node.namespaceURI) ||isHTML
			// the name is not validated when the element is created (or its prefix is changed),
			// so a ">" or whitespace in it would end the start tag early and inject markup
			if (requireWellFormed && !tagNamePattern.test(nodeName)) {
				throw new DOMException(INVALID_STATE_ERR, 'The element name "' + nodeName + '" is not a valid XML QName');
			}
			buf.push('<',nodeName);



			for(var i=0;i<len;i++){
				// add namespaces for attributes
				var attr = attrs.item(i);
				if (attr.prefix == 'xmlns') {
					visibleNamespaces.push({ prefix: attr.localName, namespace: attr.value });
				}else if(attr.nodeName == 'xmlns'){
					visibleNamespaces.push({ prefix: '', namespace: attr.value });
				}
			}
			for(var i=0;i<len;i++){
				var attr = attrs.item(i);
				if (needNamespaceDefine(attr,isHTML, visibleNamespaces)) {
					var prefix = attr.prefix||'';
					var uri = attr.namespaceURI;
					addSerializedAttribute(buf, prefix ? 'xmlns:' + prefix : "xmlns", uri, requireWellFormed);
					visibleNamespaces.push({ prefix: prefix, namespace:uri });
				}
				// attributes have no children, so this call does not nest any further
				serializeToString(attr,buf,isHTML,nodeFilter,visibleNamespaces,requireWellFormed);
			}
			// add namespace for current node
			if (needNamespaceDefine(node,isHTML, visibleNamespaces)) {
				var prefix = node.prefix||'';
				var uri = node.namespaceURI;
				addSerializedAttribute(buf, prefix ? 'xmlns:' + prefix : "xmlns", uri, requireWellFormed);
				visibleNamespaces.push({ prefix: prefix, namespace:uri });
			}

			if(child || isHTML && !/^(?:meta|link|img|br|hr|input)$/i.test(nodeName)){
				buf.push('>');
				// the end tag is written after all children (Last In First Out)
				stack.push({ closeTag: nodeName });
				//if is cdata child node
				_pushChildFrames(stack, node, isHTML, visibleNamespaces, isHTML && /^script$/i.test(nodeName));
			}else{
				buf.push('/>');
			}
			// remove added visible namespaces
			//visibleNamespaces.length = startVisibleNamespaces;
			break;
		case DOCUMENT_NODE:
		case DOCUMENT_FRAGMENT_NODE:
			_pushChildFrames(stack, node, isHTML, visibleNamespaces, false);
			break;
		case ATTRIBUTE_NODE:
			addSerializedAttribute(buf, node.name, node.value, requireWellFormed);
			break;
		case TEXT_NODE:
			buf.push(node.data.replace(/[<&]/g,_xmlEncoder));
			break;
		case CDATA_SECTION_NODE:
			if (requireWellFormed && node.data.indexOf(']]>') !== -1) {
				throw new DOMException(INVALID_STATE_ERR, 'The CDATASection data contains "]]>"');
			}
			buf.push('<![CDATA[', node.data.replace(/]]>/g, ']]]]><![CDATA[>'), ']]>');
			break;
		case COMMENT_NODE:
			if (requireWellFormed) {
				if (InvalidChar.test(node.data)) {
					throw new DOMException(INVALID_STATE_ERR, 'The comment node data contains characters outside the XML Char production');
				}
				if (node.data.indexOf('--') !== -1 || node.data[node.data.length - 1] === '-') {
					throw new DOMException(INVALID_STATE_ERR, 'The comment node data contains "--" or ends with "-"');
				}
			}
			buf.push( "<!--",node.data,"-->");
			break;
		case DOCUMENT_TYPE_NODE:
			var pubid = node.publicId;
			var sysid = node.systemId;
			if (requireWellFormed) {
				if (!tagNamePattern.test(node.name)) {
					throw new DOMException(INVALID_STATE_ERR, 'The doctype name "' + node.name + '" is not a valid XML Name');
				}
				if (pubid && !PubidChars_match.test(pubid)) {
					throw new DOMException(INVALID_STATE_ERR, 'The DocumentType publicId is not a valid PubidLiteral');
				}
				if (sysid && sysid != '.' && String(sysid).indexOf('"') !== -1 && String(sysid).indexOf("'") !== -1) {
					throw new DOMException(INVALID_STATE_ERR, 'The DocumentType systemId is not a valid SystemLiteral');
				}
				if (node.internalSubset && String(node.internalSubset).indexOf(']>') !== -1) {
					throw new DOMException(INVALID_STATE_ERR, 'The DocumentType internalSubset contains "]>"');
				}
			}
			buf.push('<!DOCTYPE ',node.name);
			if(pubid){
				buf.push(' PUBLIC ', _quoteDoctypeId(pubid));
				if (sysid && sysid!='.') {
					buf.push(' ', _quoteDoctypeId(sysid));
				}
				buf.push('>');
			}else if(sysid && sysid!='.'){
				buf.push(' SYSTEM ', _quoteDoctypeId(sysid), '>');
			}else{
				var sub = node.internalSubset;
				if(sub){
					buf.push(" [",sub,"]");
				}
				buf.push(">");
			}
			break;
		case PROCESSING_INSTRUCTION_NODE:
			if (requireWellFormed) {
				// the target is not validated when the node is created (or later assigned),
				// so it is also checked against the XML Name production here: a "?>" in it
				// would close the processing instruction early, like one in the data
				if (node.target.indexOf(':') !== -1 || node.target.toLowerCase() === 'xml' || !tagNamePattern.test(node.target)) {
					throw new DOMException(INVALID_STATE_ERR, 'The ProcessingInstruction target is not well-formed');
				}
				if (InvalidChar.test(node.data)) {
					throw new DOMException(INVALID_STATE_ERR, 'The ProcessingInstruction data contains characters outside the XML Char production');
				}
				if (node.data.indexOf('?>') !== -1) {
					throw new DOMException(INVALID_STATE_ERR, 'The ProcessingInstruction data contains "?>"');
				}
			}
			buf.push( "<?",node.target," ",node.data,"?>");
			break;
		case ENTITY_REFERENCE_NODE:
			if (requireWellFormed && !tagNamePattern.test(node.nodeName)) {
				throw new DOMException(INVALID_STATE_ERR, 'The entity reference name "' + node.nodeName + '" is not a valid XML Name');
			}
			buf.push( '&',node.nodeName,';');
			break;
		//case ENTITY_NODE:
		//case NOTATION_NODE:
		default:
			buf.push('??',node.nodeName);
		}
	}
}
/**
 * Schedules the children of `node` for serialization by `serializeToString`.
 * They are pushed from `lastChild` backwards, so `firstChild` ends up on top of the stack
 * and the children are serialized in document order.
 *
 * @param {Array} stack the serializeToString work stack
 * @param {Node} node the node whose children are scheduled
 * @param {boolean} isHTML
 * @param {Array} visibleNamespaces
 * @param {boolean} inScript `true` when `node` is a html script element, whose children
 * with data are written as is
 */
function _pushChildFrames(stack, node, isHTML, visibleNamespaces, inScript){
	var child = node.lastChild;
	while(child){
		stack.push({ node: child, isHTML: isHTML, visibleNamespaces: visibleNamespaces, inScript: inScript });
		child = child.previousSibling;
	}
}
/**
 * Imports a node from a different document into `doc`, creating a new copy.
 * Delegates to {@link walkDOM} for traversal, to avoid stack overflow on deeply nested trees
 * (GHSA-2v35-w6hq-6mfw). Each node in the subtree is shallow-cloned, stamped with `doc` as its
 * `ownerDocument`, and detached (`parentNode` set to `null`).
 * Children are imported when `deep` is `true`; for {@link Attr} nodes `deep` is always forced
 * to `true`.
 *
 * @param {Document} doc
 * The document that will own the imported node.
 * @param {Node} node
 * The node to import.
 * @param {boolean} deep
 * If `true`, descendants are imported as well.
 * @returns {Node}
 * The newly imported node, now owned by `doc`.
 */
function importNode(doc,node,deep){
	var destRoot;
	walkDOM(node, null, {
		enter: function(srcNode, destParent){
			var node2;
			var shouldDeep = deep;
			switch (srcNode.nodeType) {
			case ELEMENT_NODE:
				node2 = srcNode.cloneNode(false);
				node2.ownerDocument = doc;
				//var attrs = node2.attributes;
				//var len = attrs.length;
				//for(var i=0;i<len;i++){
					//node2.setAttributeNodeNS(importNode(doc,attrs.item(i),deep));
				//}
			case DOCUMENT_FRAGMENT_NODE:
				break;
			case ATTRIBUTE_NODE:
				shouldDeep = true;
				break;
			//case ENTITY_REFERENCE_NODE:
			//case PROCESSING_INSTRUCTION_NODE:
			////case TEXT_NODE:
			//case CDATA_SECTION_NODE:
			//case COMMENT_NODE:
			//	deep = false;
			//	break;
			//case DOCUMENT_NODE:
			//case DOCUMENT_TYPE_NODE:
			//cannot be imported.
			//case ENTITY_NODE:
			//case NOTATION_NODE：
			//can not hit in level3
			//default:throw e;
			}
			if(!node2){
				node2 = srcNode.cloneNode(false);//false
			}
			node2.ownerDocument = doc;
			node2.parentNode = null;
			// capture as the root of the imported subtree or attach to parent.
			if(destParent === null){
				destRoot = node2;
			}else{
				destParent.appendChild(node2);
			}
			// Return node2 as the context for children (causes walkDOM to descend),
			// or null to skip children (shallow import).
			return shouldDeep ? node2 : null;
		}
	});
	return destRoot;
}
//
//var _relationMap = {firstChild:1,lastChild:1,previousSibling:1,nextSibling:1,
//					attributes:1,childNodes:1,parentNode:1,documentElement:1,doctype,};
function cloneNode(doc,node,deep){
	// Iterative traversal via walkDOM to avoid stack overflow on deeply nested trees
	// (GHSA-2v35-w6hq-6mfw).
	var destRoot;
	walkDOM(node, null, {
		enter: function(srcNode, destParent){
			// 1. Create a blank node of the same type and copy all scalar own properties.
			var node2 = new srcNode.constructor();
			for (var n in srcNode) {
				if (Object.prototype.hasOwnProperty.call(srcNode, n)) {
					var v = srcNode[n];
					if (typeof v != "object") {
						if (v != node2[n]) {
							node2[n] = v;
						}
					}
				}
			}
			if(srcNode.childNodes){
				node2.childNodes = new NodeList();
			}
			node2.ownerDocument = doc;
			// 2. Handle node-type-specific setup.
			//    Attributes are not DOM children, so they are cloned inline here
			//    rather than by walkDOM descent.
			//    ATTRIBUTE_NODE forces deep=true so its own children are walked.
			var shouldDeep = deep;
			switch (node2.nodeType) {
			case ELEMENT_NODE:
				var attrs	= srcNode.attributes;
				var attrs2	= node2.attributes = new NamedNodeMap();
				var len = attrs.length
				attrs2._ownerElement = node2;
				for(var i=0;i<len;i++){
					node2.setAttributeNode(cloneNode(doc,attrs.item(i),true));
				}
				break;;
			case ATTRIBUTE_NODE:
				shouldDeep = true;
			}
			// 3. Attach to parent, or capture as the root of the cloned subtree.
			if(destParent !== null){
				destParent.appendChild(node2);
			}else{
				destRoot = node2;
			}
			// 4. Return node2 as the context for children (causes walkDOM to descend),
			//    or null to skip children (shallow clone).
			return shouldDeep ? node2 : null;
		}
	});
	return destRoot;
}

function __set__(object,key,value){
	object[key] = value
}
//do dynamic
try{
	if(Object.defineProperty){
		Object.defineProperty(LiveNodeList.prototype,'length',{
			get:function(){
				_updateLiveList(this);
				return this.$$length;
			}
		});
		Object.defineProperty(Node.prototype,'textContent',{
			get:function(){
				return getTextContent(this);
			},
			set:function(data){
				switch(this.nodeType){
				case ELEMENT_NODE:
				case DOCUMENT_FRAGMENT_NODE:
					while(this.firstChild){
						this.removeChild(this.firstChild);
					}
					if(data || String(data)){
						this.appendChild(this.ownerDocument.createTextNode(data));
					}
					break;
				default:
					//TODO:
					this.data = data;
					this.value = data;
					this.nodeValue = data;
				}
			}
		})
		
		function getTextContent(node){
			switch(node.nodeType){
			case ELEMENT_NODE:
			case DOCUMENT_FRAGMENT_NODE:
				// Iterative traversal via walkDOM to avoid stack overflow on deeply nested trees
				// (GHSA-2v35-w6hq-6mfw).
				var buf = [];
				walkDOM(node, null, {
					enter: function(n){
						if(n.nodeType === ELEMENT_NODE || n.nodeType === DOCUMENT_FRAGMENT_NODE){
							return true; // enter children
						}
						if(n.nodeType === PROCESSING_INSTRUCTION_NODE || n.nodeType === COMMENT_NODE){
							return null; // excluded from text content
						}
						buf.push(n.nodeValue);
					}
				});
				return buf.join('');
			default:
				return node.nodeValue;
			}
		}
		__set__ = function(object,key,value){
			//console.log(value)
			object['$$'+key] = value
		}
	}
}catch(e){//ie8
}

//if(typeof require == 'function'){
	exports.DOMImplementation = DOMImplementation;
	exports.XMLSerializer = XMLSerializer;
	exports.DOMException = DOMException;
	// test-only: exposes the private `find` ponyfill to test/conventions/find.js
	exports.__find = find;
	// test-only: exposes the private iterative `walkDOM` traversal to test/dom/walk-dom.js
	exports.__walkDOM = walkDOM;
//}
