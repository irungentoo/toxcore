;[c]asm-xml.asm - Asm XML Parser
;[c]
;[c]Copyright (C) 2007-12, Marc Kerbiquet
;[c]All rights reserved.
;[c]
;[c]Redistribution and use in source and binary forms, with or without
;[c]modification, are permitted provided that the following conditions are met:
;[c]
;[c]1. Redistributions of source code must retain the above copyright notice,
;[c]   this list of conditions and the following disclaimer.
;[c]2. Redistributions in binary form must reproduce the above copyright notice,
;[c]   this list of conditions and the following disclaimer in the documentation
;[c]   and/or other materials provided with the distribution.
;[c]3. Neither the name of AsmXml nor the names of its contributors may be
;[c]   used to endorse or promote products derived from this software without
;[c]   specific prior written permission.
;[c]
;[c]THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
;[c]AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
;[c]IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;[c]DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
;[c]FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
;[c]DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;[c]SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
;[c]CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
;[c]OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;[c]OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;[c]
;[c]
;[c]Open this file with Code Browser (http://code-browser.sourceforge.net/)
;[c]to view this long flat file as a structured text file.
;[c]
;[c]This is source code for  fasm.
;[c]
;[c]Conventions:
;[c]Preserved registers: ebx esi edi ebp
;[c]Scratch registers: eax ecx edx
;[c](same as Windows/Linux/BSD)
;[c]
;[of]:Macros
macro struct name
{
	virtual at 0
	label name
}

macro ends
{
.sizeof	rd	0
	end virtual
}
;[cf]
;[of]:Definitions
		struct	MemoryContext
.base		rd	1	; memory buffer
.limit		rd	1	; limit of memory buffer
.chunks		rd	1	; list of chunks
.chunkSize	rd	1	; default size of chunks
		ends		
;[c]
		struct	ParseContext
.base		rd	1	; memory buffer
.limit		rd	1	; limit of memory buffer
.chunks		rd	1	; list of chunks
.chunkSize	rd	1	; default size of chunks
.errorCode	rd	1
.source		rd	1	; address of the first char
.current	rd	1	; address of the last read char
.line		rd	1	; line number of the last read char
.column		rd	1	; column of the last read char
.root		rd	1	; root element
.version	rd	2	; version info (if any)
.encoding	rd	2	; encoding (if any)
.strict		rd	1	; 0 if not strict
.doctype	rd	1	; can read doctype
.invalidElement	rb	Element.sizeof
		ends		
;[c]
		struct	CreateClassContext
.base		rd	1	; memory buffer
.limit		rd	1	; limit of memory buffer
.chunks		rd	1	; list of chunks
.chunkSize	rd	1	; default size of chunks
.errorCode	rd	1
.line		rd	1	; line number of the last read char
.column		rd	1	; column of the last read char
.classes	rd	1	; the list of global classes
.rootClass	rd	1	; the root class
.rootElement	rd	1	; the root element
		ends
;[c]
		struct	ElementClass
.offset		rd	1	; Offset of element in parent element
				; (0 when it is a collection)
.name		rd	1	; name of the element
.nameLimit	rd	1	; limit of the name
.size		rd	1	; size to store the element
.id		rd	1	; id
.type		rd	1	; container, text or mixed
.propertyCount	rd	1	; number of attributes + text elements
.childCount	rd	1	; number of child classes
.attributes	rd	1	; list of attributes
.elements	rd	1	; list of elements
.children	rd	1	; list of child classes
				; The order is the one defined in the class
				; definition file.
.shared		rb	1	; 
.status		rb	1	; 0-unsolved 1-resolving 2-resolved
		rb	2	; padding
.source		rd	1	; source element
		ends
;[c]
		struct TextElementClass
.offset		rd	1	; Offset of attribute in element
				; (the text element is stored as an attribute)
.begin		rd	1	; element name (begin)
.limit		rd	1	; element name (last char+1)
		ends
;[c]
		struct	Element
.id		rd	1	; id of the element
.nextSibling	rd	1
.firstChild	rd	1
.lastChild	rd	1
.reserved	rd	2	; store ignored attributes here
		ends
;[c]
;[c]
		struct	Attribute
.begin		rd	1
.limit		rd	1
		ends
;[c]
;[c]
EC_TEXT		equ	1
EC_TEXT_COLL	equ	2

;[c]
;[c]Error Codes
;[c]
RC_OK				equ	0	; everything is ok
RC_MEMORY			equ	1	; out of memory

; Schema
RC_EMPTY_NAME			equ	10	; name empty or not defined
RC_ATTR_DEFINED			equ	11	; attribute already defined
RC_ELEM_DEFINED			equ	12	; element already defined
RC_SCHEMA_EMPTY			equ	13	; schema does not contains a document
RC_DOCUMENT_DEFINED		equ	14	; schema contains more than one document
RC_UNDEFINED_CLASS		equ	15	; can't find collection in reference
RC_UNDEFINED_GROUP		equ	16	; can't find a group in include
RC_INVALID_ID			equ	17	; id is not a valid number
RC_INVALID_IGNORE		equ	18	; ignore is not 'yes' or 'no'
RC_RECURSIVE_ELEMENT		equ	19	; element cannot reference itself

; Parsing
RC_INVALID_ENTITY_REFERENCE	equ	20
RC_UNEXPECTED_END		equ	21
RC_INVALID_CHAR			equ	22
RC_OVERFLOW			equ	23
RC_NO_START_TAG			equ	24
RC_TAG_MISMATCH			equ	25
RC_INVALID_TAG			equ	26
RC_INVALID_ATTRIBUTE		equ	27
RC_INVALID_PI			equ	28
RC_INVALID_DOCTYPE		equ	29
RC_VERSION_EXPECTED		equ	30

;[c]
;[c]Various constants
;[c]
TAB_SIZE		equ	8
DEFAULT_CHUNK_SIZE	equ	1024*1024
HEADER_SIZE		equ	16	; reserved space for chunks
;[c]
TYPE_CONTAINER		equ	0
TYPE_TEXT		equ	1
TYPE_MIXED		equ	2
;[c]
ATTR_NAME		equ	0
ATTR_IGNORE		equ	1
ATTR_TYPE		equ	2
ATTR_ID			equ	3
;[c]
;[c]Class Ids
;[c]
schemaId		equ	0
documentId		equ	1
attributeId		equ	2
textId			equ	3
collectionId		equ	4
elementId		equ	5
referenceId		equ	6
includeId		equ	7
groupId			equ	8
;[c]
;[c]Resolution
;[c]
UNRESOLVED		equ	0
RESOLVING		equ	1
RESOLVED		equ	2
;[c]
;[c]Atoms (for DOCTYPE)
;[c]
ATOM_DOCTYPE		equ	0
ATOM_ELEMENT		equ	1
ATOM_ATTLIST		equ	2
ATOM_PCDATA		equ	3
ATOM_IMPLIED		equ	4
ATOM_REQUIRED		equ	5
ATOM_FIXED		equ	6
ATOM_NDATA		equ	7

ATOM_CDATA		equ	8
ATOM_ID			equ	9
ATOM_IDREF		equ	10
ATOM_IDREFS		equ	11
ATOM_ENTITY		equ	12
ATOM_ENTITIES		equ	13
ATOM_NMTOKEN		equ	14
ATOM_NMTOKENS		equ	15
ATOM_NOTATION		equ	16

ATOM_VERSION		equ	17
ATOM_ENCODING		equ	18
ATOM_STANDALONE		equ	19
;[cf]
;[of]:Documentation
;[c]
;[c]Element Map
;[c]
;[c]	An element map is an array of 256 values each value correspond to
;[c]	an action to take corresponding to the current read char:
;[c]	* 1
;[c]		The character is invalid in the current state
;[c]	
;[c]	* Address % 4 = 0
;[c]		The address of the element map for the next char
;[c]	
;[c]	* Address  % 4 = 1
;[c]		The address of the element class found preceded by the
;[c]		remaining chars and the type of class
;[c]		e.g.
;[c]			"bcd", 0, t, padding, ...
;[c]		* t = 0
;[c]			It is a collection, the pointer to the element class 
;[c]			is at the next 4 byte align.
;[c]		* t = 1
;[c]			It is a text element, the text element class is stored
;[c]			after the padding.
;[c]	
;[c]	* Address % 4 = 3
;[c]		Same as previous but all chars have already been read.
;[c]		It is used when a name is the prefix of another name.
;[c]		e.g.:
;[c]		<ab>
;[c]		<abc>
;[c]		
;[c]
;[c]			
;[c]		
;[cf]
;[of]:C Stubs
;[of]:initialize
;[c]Initialize the library
;[c]
;[c]	void ax_initialize(malloc, free)
;[c]
;[c]ARGUMENTS
;[c]	malloc
;[c]		the memory alllocation function
;[c]	free
;[c]		the free memory function
;[c]
;[c]
_initialize:	push	ebx
		mov	eax,[esp+8+0]
		mov	ebx,[esp+8+4]
		call	initialize
		pop	ebx
		ret
;[cf]
;[of]:initializeParser
;[c]Initialize the parse context
;[c]
;[c]	errorCode = ax_initializeParser(context, chunkSize)
;[c]
;[c]ARGUMENTS
;[c]	context
;[c]		the parse context.
;[c]	chunkSize
;[c]		the default size of chunk
;[c]
;[c]RETURN VALUE
;[c]	The error code
;[c]
_initializeParser:
		push	ebp
		mov	ebp,[esp+8+0]
		mov	ecx,[esp+8+4]
		call	initializeParser
		pop	ebp
		ret
;[cf]
;[of]:releaseParser
;[c]Release the parse context
;[c]
;[c]	ax_releaseParser(context)
;[c]
;[c]ARGUMENTS
;[c]	context
;[c]		the parse context. The memory base and memory limit must be 
;[c]		initialized.
;[c]
_releaseParser:	push	ebp
		mov	ebp,[esp+8+0]
		call	releaseParser
		pop	ebp
		ret
;[cf]
;[of]:parse
;[c]Parse an XML string
;[c]
;[c]	Element* ax_parse(context, source, type, strict)
;[c]
;[c]ARGUMENTS
;[c]	context
;[c]		the parse context. The object must have been initialized.
;[c]	source
;[c]		the xml to parse
;[c]	type
;[c]		the expected type of element to parse
;[c]
;[c]RETURN VALUE
;[c]	The created element or null if an error occured.
;[c]
_parse:		push	ebx
		push	esi
		push	edi
		push	ebp

		mov	ebp,[esp+20+ 0]
		mov	esi,[esp+20+ 4]
		mov	edx,[esp+20+ 8]
		mov	edi,[esp+20+12]
		call	parse

		mov	[ebp+ParseContext.current],esi
		mov	[ebp+ParseContext.errorCode],eax
		jz	.ok
		call	computeLineColumn
		xor	eax,eax
		jmp	.error

.ok:		mov	eax,[ebp+ParseContext.root]
.error:		pop	ebp
		pop	edi
		pop	esi
		pop	ebx
		ret
;[c]
;[cf]
;[c]
;[of]:initializeClassParser
;[c]Initialize the class parser
;[c]
;[c]	errorCode = ax_initializeClassParser(context)
;[c]
;[c]ARGUMENTS
;[c]	context
;[c]		the class parser.
;[c]
;[c]RETURN VALUE
;[c]	The error code
;[c]
_initializeClassParser:
		push	ebp
		mov	ebp,[esp+8+0]
		call	initializeClassParser
		pop	ebp
		ret
;[cf]
;[of]:releaseClassParser
;[c]Release the class parser
;[c]
;[c]	ax_releaseClassParser(context)
;[c]
;[c]ARGUMENTS
;[c]	context
;[c]		the class parser.
;[c]
_releaseClassParser:
		push	ebp
		mov	ebp,[esp+8+0]
		call	releaseClassParser
		pop	ebp
		ret
;[cf]
;[of]:classFromElement
;[c]Create a class from an element
;[c]
;[c]	ElementClass* ax_classFromElement(element, context)
;[c]
;[c]ARGUMENTS
;[c]	element
;[c]		the xml element describing the class
;[c]	context
;[c]		the class context.
;[c]
;[c]RETURN VALUE
;[c]	The created class or null if an error occured.
;[c]
_classFromElement:
		push	esi
		push	edi
		push	ebp

		mov	esi,[esp+16]
		mov	ebp,[esp+16+4]
		call	classFromElement
		mov	[ebp+CreateClassContext.errorCode],eax
		jnz	.failed
		mov	eax,[ebp+CreateClassContext.rootClass]

.error:		pop	ebp
		pop	edi
		pop	esi
		ret

.failed:	xor	eax,eax
		jmp	.error
;[c]
;[cf]
;[of]:classFromString
;[c]Create a class from a string
;[c]
;[c]	ElementClass* ax_classFromString(string, context)
;[c]
;[c]ARGUMENTS
;[c]	string
;[c]		the xml element describing the class
;[c]	context
;[c]		the class context.
;[c]
;[c]RETURN VALUE
;[c]	The created class or null if an error occured.
;[c]
_classFromString:
		push	ebx
		push	esi
		push	edi
		push	ebp
		
		mov	esi,[esp+20+0]
		mov	ebp,[esp+20+4]
		call	classFromString
		mov	[ebp+CreateClassContext.errorCode],eax
		jnz	.failed
		mov	eax,[ebp+CreateClassContext.rootClass]
		
.error:		pop	ebp
		pop	edi
		pop	esi
		pop	ebx
		ret

.failed:	xor	eax,eax
		jmp	.error
;[cf]
;[cf]
;[of]:Functions
;[of]:initialize
;[c]Initialize the library
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		the allocator function
;[c]	ebx
;[c]		the free memory function
;[c]
initialize:
	mov	[mallocFunction],eax
	mov	[freeFunction],ebx
	ret
;[cf]

;[of]:initializeParser
;[c]Initialize the parse context object
;[c]
;[c]ARGUMENTS
;[c]	ebp
;[c]		the parse context
;[c]	ecx	
;[c]		chunk size
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]
initializeParser:
		xor	eax,eax
		mov	[ebp+ParseContext.chunkSize],ecx
		mov	[ebp+ParseContext.chunks],eax
		mov	eax,ecx
		jmp	newChunk
;[cf]
;[of]:releaseParser
;[c]Release the parse context object
;[c]
;[c]ARGUMENTS
;[c]	ebp
;[c]		the parse context
;[c]
releaseParser:	jmp	releaseChunks
;[cf]
;[of]:parse
;[c]parse
;[c]
;[c]ARGUMENTS
;[c]	edx
;[c]		the type of the root element
;[c]	esi
;[c]		source
;[c]	edi
;[c]		strict flag
;[c]	ebp
;[c]		Parse context
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]	esi
;[c]		Address of the first byte after the element.
;[c]	edi
;[c]		???
;[c]
parse:		mov	[ebp+ParseContext.source],esi
		mov	[ebp+ParseContext.strict],edi
		mov	[ebp+ParseContext.doctype],1

		sub	eax,eax
		mov	[ebp+ParseContext.version+Attribute.begin],eax
		mov	[ebp+ParseContext.version+Attribute.limit],eax
		mov	[ebp+ParseContext.encoding+Attribute.begin],eax
		mov	[ebp+ParseContext.encoding+Attribute.limit],eax

		; Allocate memory for root element
		mov	edi,[ebp+ParseContext.base]
		mov	eax,[ebp+ParseContext.limit]
		mov	ebx,edi
		add	ebx,[edx+ElementClass.size]
		cmp	ebx,eax
		jae	parseChunkFull
		mov	[ebp+ParseContext.base],ebx
		mov	[ebp+ParseContext.root],edi

resumeParseChunkFull:

		; Clear higher bits of eax
		; All the functions assume that the high bits of eax
		; are always zero.
		xor	eax,eax

		call	readProlog
		jnz	return
		
		call	readRootElement
		jnz	return
		
		; forbid the doctype
		mov	[ebp+ParseContext.doctype],0

		call	readMisc
		jnz	return
		
		; error if there is remaining chars
		or	al,al
		jnz	invalidChar
		
		xor	eax,eax
		ret
;[c]
;[c]Sub-functions
;[c]
;[of]:	readRootElement
readRootElement:
		cmp	al,'<'
		jnz	notStartTag

;[of]:	Initialize Element
		mov	eax,[edx+ElementClass.id]
		mov	[edi+Element.id],eax
		xor	eax,eax
		mov	[edi+Element.firstChild],eax
		mov	[edi+Element.lastChild],eax
		mov	[edi+Element.nextSibling],eax

		mov	ecx,[edx+ElementClass.propertyCount]
		lea	ebx,[edi+Element.sizeof]

		or	ecx,ecx
		jz	.m0

		shr	ecx,1
		jnc	.m2
		mov	[ebx+Attribute.begin],eax
		mov	[ebx+Attribute.limit],eax
		jz	.m0
		add	ebx,Attribute.sizeof

.m2:		shr	ecx,1
		jnc	.m4
		mov	[ebx+Attribute.begin],eax
		mov	[ebx+Attribute.limit],eax
		mov	[ebx+Attribute.sizeof+Attribute.begin],eax
		mov	[ebx+Attribute.sizeof+Attribute.limit],eax
		jz	.m0
		add	ebx,Attribute.sizeof*2

.m4:		mov	[ebx+Attribute.sizeof*0+Attribute.begin],eax
		mov	[ebx+Attribute.sizeof*0+Attribute.limit],eax
		mov	[ebx+Attribute.sizeof*1+Attribute.begin],eax
		mov	[ebx+Attribute.sizeof*1+Attribute.limit],eax
		mov	[ebx+Attribute.sizeof*2+Attribute.begin],eax
		mov	[ebx+Attribute.sizeof*2+Attribute.limit],eax
		mov	[ebx+Attribute.sizeof*3+Attribute.begin],eax
		mov	[ebx+Attribute.sizeof*3+Attribute.limit],eax
		add	ebx,Attribute.sizeof*4
		dec	ecx
		jnz	.m4
.m0:
;[cf]
;[of]:	Read Element Name
;[c]Read Element Name
;[c]
		mov	ebx,edi
		mov	edi,[edx+ElementClass.name]
		mov	ecx,[edx+ElementClass.nameLimit]
.loop:		cmpsb
		jnz	invalidTag
		cmp	edi,ecx
		jnz	.loop
		mov	edi,ebx
		
		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'>'
		jz	readContent
		cmp	al, '/'
		jz	endOfElement
		test	byte [S + eax], 1
		jz	invalidChar
;[cf]
;[of]:	Read Attributes
;[c]Read Attributes
;[c]
;[c]Read the next attribute (skip blanks first)
;[c]
nextAttribute:
		; Skip blanks
.sb:		movzx	eax,byte [esi]
		add	esi,1
		test	byte [S + eax], 1
		jnz	.sb

;[c]
;[c]Read the next attribute (blanks already skipped, first char already read)
;[c]
readAttributes:	
		; No more attributes ?
		cmp	al, '>'
		jz	readContentOrText
		cmp	al, '/'
		jz	endOfElement
		
;[c]
;[c]Read and Decode Attribute Name
;[c]
readAttribute:	mov	ebx,[edx+ElementClass.attributes]
		mov	ecx,[ebx+eax*4]		; first char already loaded
		test	ecx,1
		jnz	.j2
.l2:		movzx	eax,byte [esi]
		mov	ecx,[ecx+eax*4]
		add	esi,1
		test	ecx,1
		jz	.l2

		test	ecx,2
		jnz	terminalAttribute
.j2:		sub	ecx,1
		jz	invalidAttribute
		align	4
.l21:		movzx	eax,byte [esi]
		add	ecx,1
		add	esi,1
		cmp	[ecx-1],al
		jz	.l21
		test	byte [ecx-1],255
		jnz	invalidAttribute

commonAttribute:
		mov	ebx,edi
		add	ebx,[ecx]

;[c]
;[c]Skip Blanks and Equal Sign
;[c]		
		cmp	al,'='			; I'm feeling lucky
		jz	readAttributeValue	;

		test	byte [S + eax], 1	; Not '=', it MUST be a blank
		jz	invalidAttribute	; or it is an invalid attribute

.skipBlank2:	movzx	eax,byte [esi]
		add	esi,1
		test	byte [S + eax], 1
		jnz	.skipBlank2

		cmp	al,'='
		jnz	invalidChar

readAttributeValue:
		movzx	eax,byte [esi]
		add	esi,1
		test	byte [S + eax], 1
		jnz	readAttributeValue

		cmp	al,$27	; '
		jz	.value
		cmp	al,'"'
		jnz	invalidChar
.value:		mov	cl,al

;[c]
;[c]Read and Store Value
;[c]	
		cmp	[ebx+Attribute.begin],0
		jnz	attributeDefinedOrIgnored
resumeBecauseIgnored:
		mov	[ebx+Attribute.begin],esi
		mov	ch,'&'
.l3:		mov	al,[esi]
		add	esi,1
		;test	byte [RAC + eax], 1	; slower but it would allow
		;jz	.l3			; detection of < in attribute
		;cmp	al,'<'			; makes the parser 5% slower
		;jz	invalidChar		;
		cmp	al,ch
		jz	attributeReference
		or	al,al
		jz	unexpectedEnd
		cmp	al,cl
		jnz	.l3
	
		lea	ecx,[esi-1]
		mov	[ebx+Attribute.limit],ecx
;[c]
endOfAttribute:
		; Read next char
		movzx	eax,byte [esi]
		add	esi,1
		
		; Is it a blank ?
		test	byte [S + eax], 1
		jnz	nextAttribute
		
		; Is it a closing tag ?
		cmp	al, '>'
		jz	readContentOrText
		
		; Is it not the end of the element ?
		cmp	al, '/'
		jnz	readAttribute

endOfElement:	movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'>'
		jnz	invalidChar
		xor	eax,eax
		ret
;[c]
terminalAttribute:
		and	ecx,not 2
		jmp	commonAttribute
;[c]
attributeDefinedOrIgnored:
		mov	eax,ebx
		sub	eax,edi
		cmp	eax,Element.reserved
		jz	resumeBecauseIgnored
		jmp	attributeDefined
;[cf]

;[of]:	Read Content
;[c]Read Content
;[c]
readContentOrText:
		; test if the content is just text
		cmp	[edx+ElementClass.type],TYPE_TEXT
		jz	readInnerText
;[c]
readContent:
		cmp	[edx+ElementClass.type],TYPE_MIXED
		jz	readPCDATA
		mov	bl,'<'

.loop:		mov	al,[esi]
		or	al,al
		jz	unexpectedEnd
		add	esi,1
		cmp	al,bl
		jnz	.loop

		mov	al,[esi]
		cmp	al, '/'
		jnz	referenceOrComment

;[of]:Read Close Tag
readCloseTag:
		add	esi,1

		mov	edi,[edx+ElementClass.name]
		mov	ecx,[edx+ElementClass.nameLimit]
.loop:		cmpsb
		jnz	closeTagMismatch
		cmp	edi,ecx
		jnz	.loop
		
		movzx	eax,byte [esi]
		add	esi,1
		cmp	al, '>'		; I'm feeling lucky
		jnz	.skipBlanks4	;
		xor	eax,eax
		ret
		
.skipBlanks4:	test	byte [S + eax], 1
		jz	invalidChar
.skipBlank4:	movzx	eax,byte [esi]
		add	esi,1
		test	byte [S + eax], 1
		jnz	.skipBlank4
		cmp	al, '>'
		jnz	invalidChar
		
		xor	eax,eax		; element successfully read
		ret
;[cf]

referenceOrComment:
		cmp	al,'!'
		jz	skipCommentOrCDATA
		cmp	al,'?'
		jz	skipContentPI
;[of]:Read Child Element
;[c]Read a child element (may be a text-only element)
;[c]
readChild:	add	esi,1
;[c]
;[c]Decode Element Name
;[c]
		mov	ebx,[edx+ElementClass.elements]
		mov	ecx,[ebx+eax*4]		; first char already loaded
		test	ecx,1
		jnz	.skip
.loop:		movzx	eax,byte [esi]
		mov	ecx,[ecx+eax*4]
		add	esi,1
		test	ecx,1
		jz	.loop
		
.skip:		test	ecx,2
		jnz	terminalElement
		dec	ecx
		jz	invalidElement
.loop2:		movzx	eax,byte [esi]
		add	ecx,1
		add	esi,1
		cmp	[ecx-1],al
		jz	.loop2
		test	byte [ecx-1],255
		jnz	invalidElement

		mov	bl,[ecx]

;[of]:Skip Blanks
		test	byte [S + eax], 1
		jz	.eNotBlank1
.eSkipBlank1:	movzx	eax,byte [esi]
		add	esi,1
		test	byte [S + eax], 1
		jnz	.eSkipBlank1
.eNotBlank1:
;[cf]

		add	ecx,3+1
		and	ecx,$FFFFFFFC
		test	bl,1
		jz	readChildElement

;[c]
;[of]:Read Text
;[c]Read a Text-Only Element
;[c]	
;[c]	* esi is the source
;[c]	* edi is the element
;[c]
;[c]	* ecx is the text element descriptor
;[c]	* al is the last non blank character in the tag (must be '>')
;[c]
readText:
		mov	ebx,edi
		add	ebx,[ecx+TextElementClass.offset]
		
		cmp	al,'/'
		jz	emptyText
		cmp	al,'>'
		jnz	invalidChar

		mov	[ebx+Attribute.begin],esi

		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'<'
		jz	emptyOrCDATAOrPI
		or	al,al
		jz	unexpectedEnd
		cmp	al,'&'
		jz	textReference

.loop:		movzx	eax,byte [esi]
		add	esi,1
		or	al,al
		jz	unexpectedEnd
		cmp	al,'&'
		jz	textReference
		cmp	al,'<'
		jnz	.loop

		movzx	eax,byte [esi]
		cmp	al,'!'
		jz	textCommentOrCDATA
		cmp	al,'?'
		jz	textPI

endOfEmptyText:	sub	esi,1
		mov	[ebx+Attribute.limit],esi
		add	esi,1

endOfText:	add	esi,1
		cmp	al, '/'
		jnz	invalidChar

		mov	ebx,edi
		mov	edi,[ecx+TextElementClass.begin]
		mov	ecx,[ecx+TextElementClass.limit]
.loop:		cmpsb
		jnz	tagMismatch
		cmp	edi,ecx
		jnz	.loop
		mov	edi,ebx
		
.eSkipBlank2:	movzx	eax,byte [esi]
		add	esi,1
		test	byte [S + eax], 1
		jnz	.eSkipBlank2
		
		cmp	al,'>'
		jz	readContent
		jmp	invalidChar
;[c]
emptyOrCDATAOrPI:
		movzx	eax,byte [esi]
		cmp	al,'?'
		jz	textPI
		cmp	al,'!'
		jnz	endOfEmptyText
		cmp	byte [esi+1],'['
		jnz	invalidCharOrComment
		cmp	byte [esi+2],'C'
		jnz	invalidChar
		cmp	byte [esi+3],'D'
		jnz	invalidChar
		cmp	byte [esi+4],'A'
		jnz	invalidChar
		cmp	byte [esi+5],'T'
		jnz	invalidChar
		cmp	byte [esi+6],'A'
		jnz	invalidChar
		cmp	byte [esi+7],'['
		jnz	invalidChar
		add	esi,8
		mov	[ebx+Attribute.begin],esi

.loop:		movzx	eax,byte [esi]
		add	esi,1
		or	al,al
		jz	unexpectedEnd
		cmp	al,']'
		jnz	.loop
		movzx	eax,byte [esi]
		cmp	al,']'
		jnz	.loop
		mov	al,[esi+1]
		cmp	al,'>'
		jnz	.loop

		mov	al,[esi+2]
		cmp	al,'<'
		jnz	.mixed

		sub	esi,1
		mov	[ebx+Attribute.limit],esi
		add	esi,4
		movzx	eax,byte [esi]
		jmp	endOfText
;[c]
;[c]The text starts with a CDATA section but contain something else,
;[c]let 's read it again with the slow method
;[c]
.mixed:		mov	esi,[ebx+Attribute.begin]
		sub	esi,9		; size("<![CDATA[")
		mov	[ebx+Attribute.begin],esi
		call	readValue
		jmp	endOfText
;[c]
textReference:
textCommentOrCDATA:
textPI:
invalidCharOrComment:
		sub	esi,1
		call	readValue
		jmp	endOfText
;[c]
emptyText:	movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'>'
		jnz	invalidChar
		mov	[ebx+Attribute.begin],esi	; any non null ptr is ok
		mov	[ebx+Attribute.limit],esi
		jmp	readContent
;[cf]
;[of]:Read a Child Element
;[c]Read a Child Element
;[c]
;[c]	* esi source
;[c]	* edi parent element
;[c]	* ecx the element description in parent
;[c]	* edx type of parent
;[c]

readChildElement:
		
		push	edx
		mov	edx,[ecx]
		
		; Allocate memory
		mov	ecx,[ebp+ParseContext.base]
		mov	ebx,[edx+ElementClass.size]
		add	ebx,ecx
		cmp	ebx,[ebp+ParseContext.limit]
		jae	.chunkFull
		mov	[ebp+ParseContext.base],ebx
.resume:
		; It is an element, not a collection:
		; it must be store in an attribute slot instead of
		; in the list of children.
		; This case should be exceptional, it is placed
		; out of the main flow to avoid breaking the pipeline
		cmp	[edx+ElementClass.offset],0
		jnz	.element
	
		; Append element
		cmp	dword [edi+Element.firstChild],0
		jnz	.rce1
		mov	[edi+Element.firstChild],ecx
.rce1:		mov	ebx,[edi+Element.lastChild]
		or	ebx,ebx
		jz	.rce2
		mov	[ebx+Element.nextSibling],ecx
.rce2:		mov	[edi+Element.lastChild],ecx

.resume2:	push	edi
		mov	edi,ecx
;[of]:	Initialize Element
		push	eax
		mov	eax,[edx+ElementClass.id]
		mov	[edi+Element.id],eax
		xor	eax,eax
		mov	[edi+Element.firstChild],eax
		mov	[edi+Element.lastChild],eax
		mov	[edi+Element.nextSibling],eax

		mov	ecx,[edx+ElementClass.propertyCount]
		lea	ebx,[edi+Element.sizeof]

		or	ecx,ecx
		jz	.xm0

		shr	ecx,1
		jnc	.xm2
		mov	[ebx+Attribute.begin],eax
		mov	[ebx+Attribute.limit],eax
		jz	.xm0
		add	ebx,Attribute.sizeof

.xm2:		shr	ecx,1
		jnc	.xm4
		mov	[ebx+Attribute.begin],eax
		mov	[ebx+Attribute.limit],eax
		mov	[ebx+Attribute.sizeof+Attribute.begin],eax
		mov	[ebx+Attribute.sizeof+Attribute.limit],eax
		jz	.xm0
		add	ebx,Attribute.sizeof*2

.xm4:		mov	[ebx+Attribute.sizeof*0+Attribute.begin],eax
		mov	[ebx+Attribute.sizeof*0+Attribute.limit],eax
		mov	[ebx+Attribute.sizeof*1+Attribute.begin],eax
		mov	[ebx+Attribute.sizeof*1+Attribute.limit],eax
		mov	[ebx+Attribute.sizeof*2+Attribute.begin],eax
		mov	[ebx+Attribute.sizeof*2+Attribute.limit],eax
		mov	[ebx+Attribute.sizeof*3+Attribute.begin],eax
		mov	[ebx+Attribute.sizeof*3+Attribute.limit],eax
		add	ebx,Attribute.sizeof*4
		dec	ecx
		jnz	.xm4

.xm0:		pop	eax
;[cf]
		call	readAttributes
		pop	edi
		pop	edx
		jz	readContent
		ret
;[c]
.element:	mov	ebx,[edx+ElementClass.offset]
		cmp	[edi+ebx+Attribute.begin],0
		jnz	.elementDefined
		mov	[edi+ebx+Attribute.begin],ecx
		jmp	.resume2

.elementDefined:
		pop	edx
		jmp	elementDefined
;[c]
.chunkFull:	push	eax
		push	edx
		push	edi
		mov	eax,[edx+ElementClass.size]
		call	extendMemory
		mov	ecx,edi
		pop	edi
		pop	edx
		pop	eax
		jz	.resume
		pop	edx
		jmp	parseOutOfMemory
;[cf]
;[c]
terminalElement:
		add	ecx,1
		mov	bl,[ecx-3]

;[of]:Skip Blanks
		test	byte [S + eax], 1
		jz	.eNotBlank1
.eSkipBlank1:	movzx	eax,byte [esi]
		add	esi,1
		test	byte [S + eax], 1
		jnz	.eSkipBlank1
.eNotBlank1:
;[cf]

		test	bl,1
		jz	readChildElement
		jmp	readText		
;[cf]
;[of]:Skip comment
skipCommentOrCDATA:
		add	esi,1
		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'-'
		jz	.comment
;[c]
.CDATA:		cmp	al,'['
		jnz	invalidChar
		cmp	byte [esi],'C'
		jnz	invalidChar
		cmp	byte [esi+1],'D'
		jnz	invalidChar
		cmp	byte [esi+2],'A'
		jnz	invalidChar
		cmp	byte [esi+3],'T'
		jnz	invalidChar
		cmp	byte [esi+4],'A'
		jnz	invalidChar
		cmp	byte [esi+5],'['
		jnz	invalidChar
		add	esi,6

.cd1:		movzx	eax,byte [esi]
		add	esi,1
		or	al,al
		jz	unexpectedEnd
		cmp	al,']'
		jnz	.cd1
		movzx	eax,byte [esi]
		cmp	al,']'
		jnz	.cd1
		mov	al,[esi+1]
		cmp	al,'>'
		jnz	.cd1
		add	esi,2
		jmp	readContent
;[c]
.comment:	call	readComment
		jnz	return
		jmp	readContent
;[cf]
;[of]:Skip processing instruction
skipContentPI:	call	readPI
		jnz	return
		jmp	readContent
;[cf]
;[c]
;[of]:Read Inner Text
;[c]Read a Text-Only Element
;[c]	
;[c]	* esi is the source
;[c]	* edi is the element
;[c]	* edx is the type of the element
;[c]
;[c]	* al is the last non blank character in the tag (must be '>')
;[c]
readInnerText:	lea	ebx,[edi+Element.sizeof]
		mov	[ebx+Attribute.begin],esi

		mov	ecx,'&' * 256 + '<'

		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,cl
		jz	innerEmptyOrCDATAOrPI
		or	al,al
		jz	unexpectedEnd
		cmp	al,ch
		jz	innerTextReference

.loop:		movzx	eax,byte [esi]
		add	esi,1
		or	al,al
		jz	unexpectedEnd
		cmp	al,ch
		jz	innerTextReference
		cmp	al,cl
		jnz	.loop

		movzx	eax,byte [esi]
		cmp	al,'!'
		jz	innerTextCommentOrCDATA
		cmp	al,'?'
		jz	innerPI

innerEndOfEmptyText:	
		dec	esi
		mov	[ebx+Attribute.limit],esi
		inc	esi

innerEndOfText:	cmp	al, '/'
		jnz	invalidChar
		jmp	readCloseTag
;[c]
innerEmptyOrCDATAOrPI:
		movzx	eax,byte [esi]
		cmp	al,'?'
		jz	innerPI
		cmp	al,'!'
		jnz	innerEndOfEmptyText
		cmp	byte [esi+1],'['
		jnz	innerInvalidCharOrComment
		cmp	byte [esi+2],'C'
		jnz	invalidChar
		cmp	byte [esi+3],'D'
		jnz	invalidChar
		cmp	byte [esi+4],'A'
		jnz	invalidChar
		cmp	byte [esi+5],'T'
		jnz	invalidChar
		cmp	byte [esi+6],'A'
		jnz	invalidChar
		cmp	byte [esi+7],'['
		jnz	invalidChar
		add	esi,8
		mov	[ebx+Attribute.begin],esi

.loop:		movzx	eax,byte [esi]
		add	esi,1
		or	al,al
		jz	unexpectedEnd
		cmp	al,']'
		jnz	.loop
		movzx	eax,byte [esi]
		cmp	al,']'
		jnz	.loop
		mov	al,[esi+1]
		cmp	al,'>'
		jnz	.loop

		mov	al,[esi+2]
		cmp	al,'<'
		jnz	.mixed

		sub	esi,1
		mov	[ebx+Attribute.limit],esi
		add	esi,4
		movzx	eax,byte [esi]
		jmp	innerEndOfText
;[c]
;[c]The text starts with a CDATA section but contain something else,
;[c]let 's read it again with the slow method
;[c]
.mixed:		mov	esi,[ebx+Attribute.begin]
		sub	esi,9		; size("<![CDATA[")
		mov	[ebx+Attribute.begin],esi
		call	readValue
		jmp	innerEndOfText
;[c]
innerTextCommentOrCDATA:
innerTextReference:
innerInvalidCharOrComment:
innerPI:
		sub	esi,1
		call	readValue
		jmp	innerEndOfText
;[cf]
;[of]:Read PCDATA
;[c]Read Character Data in  a mixed content element
;[c]
;[c]	* esi source
;[c]	* edx type of element
;[c]	* edi the element
;[c]	
readPCDATA:	; Check that the segment is not empty
		movzx	eax,byte [esi]
		cmp	al,'<'
		jz	interEmptyOrCDATA
		or	al,al
		jz	unexpectedEnd

		; Allocate memory for element
interResume0:	mov	ecx,[ebp+ParseContext.base]
		lea	ebx,[ecx+Element.sizeof+Attribute.sizeof]
		cmp	ebx,[ebp+ParseContext.limit]
		jae	interChunkFull
		mov	[ebp+ParseContext.base],ebx
interResume:	
		; Append CharData element
		cmp	dword [edi+Element.firstChild],0
		jnz	.rce1
		mov	[edi+Element.firstChild],ecx
.rce1:		mov	ebx,[edi+Element.lastChild]
		or	ebx,ebx
		jz	.rce2
		mov	[ebx+Element.nextSibling],ecx
.rce2:		mov	[edi+Element.lastChild],ecx

		; Initialize element
		; Children fields (firstchild, ...)
		; are not initialized
		sub	ebx,ebx
		mov	[ecx+Element.id],ebx
		mov	[ecx+Element.nextSibling],ebx
		mov	[ecx+Element.sizeof+Attribute.begin],esi
		lea	ebx,[ecx+Element.sizeof]
		add	esi,1
		jmp	.first

.loop:		movzx	eax,byte [esi]
		add	esi,1
		or	al,al
		jz	unexpectedEnd
.first:		cmp	al,'&'
		jz	interTextReference
		cmp	al,'<'
		jnz	.loop

		movzx	eax,byte [esi]
		cmp	al,'!'
		jz	interTextCommentOrCDATA
		cmp	al,'?'
		jz	interTextPI

		dec	esi
		mov	[ebx+Attribute.limit],esi
		inc	esi

interEndOfText:	cmp	al, '/'
		jnz	referenceOrComment
		jmp	readCloseTag
;[c]
interEmptyOrCDATA: ; or comment
		add	esi,1
		movzx	eax,byte [esi]
		cmp	al,'?'
		jz	.resume
		cmp	al,'!'
		jnz	interEndOfText
.resume:	sub	esi,1
		movzx	eax,byte [esi]
		jmp	interResume0
;[c]
interTextCommentOrCDATA:
interTextReference:
interTextPI:
		sub	esi,1
		call	readValue
		jmp	interEndOfText
;[c]
interChunkFull:	push	eax
		push	edx
		push	edi
		mov	eax,Element.sizeof + Attribute.sizeof
		call	extendMemory
		mov	ecx,edi
		pop	edi
		pop	edx
		pop	eax
		jz	interResume
		jmp	parseOutOfMemory
;[cf]
;[cf]
;[of]:	attributeReference
attributeReference:
		push	ecx
		push	edx
		push	edi
;[c]
;[c]Count chars
;[c]
		mov	ah,cl
		lea	ecx,[esi-1]
.l1:		mov	al,[esi]
		add	esi,1
		or	al,al
		jz	.unexpectedEnd
		cmp	al,ah
		jnz	.l1
		mov	edx,esi
		mov	esi,[ebx+Attribute.begin]
		sub	ecx,esi	; length of first part
		sub	edx,esi	; maximum length
;[c]		
;[c]Pre-reserve sufficient space
;[c]		
		mov	edi,[ebp+ParseContext.base]
		add	edx,edi
		cmp	edx,[ebp+ParseContext.limit]
		jae	.chunkFull
.resume:	mov	[ebx+Attribute.begin],edi
;[c]
;[c]Copy first part
;[c]
		rep 
		movsb
		add	esi,1
		
		mov	cl,ah	; restore sting delimiter
		xor	ah,ah	; restore ah to 0
;[c]
;[c]Copy remaining chars
;[c]
;[c]	Note: it is no longer required to check for unexpected end in 
;[c]	this loop since we have already scanned the value while counting 
;[c]	chars.
;[c]		
.decode:	call	decodeReference
.loop:		stosb
		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'&'
		jz	.decode
		cmp	al,cl
		jnz	.loop

		mov	[ebx+Attribute.limit],edi
;[c]		
;[c]Free remaining space (align on the next dword)
;[c]
		add	edi,3
		and	edi,not 3
		mov	[ebp+ParseContext.base],edi
		pop	edi
		pop	edx
		pop	ecx

		; Terminate this attribute and go to the next one
		jmp	endOfAttribute
;[c]
.chunkFull:	push	eax
		push	ecx
		push	edx
		mov	eax,edx
		sub	eax,edi
		call	extendMemory
		pop	edx
		pop	ecx
		pop	eax
		jz	.resume

		pop	edi
		pop	edx
		pop	ecx
		jmp	parseOutOfMemory
;[c]
.unexpectedEnd:	pop	edi
		pop	edx
		pop	ecx
		jmp	unexpectedEnd
;[cf]

;[cf]
;[of]:	readValue
;[c]Read a text value 
;[c]
;[c]ARGUMENTS
;[c]	ebx
;[c]		attribute (begin contains the beginning of text)
;[c]	esi
;[c]		source points to first special char (< or &)
;[c]
readValue:	push	ecx
		push	edx
		push	edi
;[c]
;[c]Count chars
;[c]
		mov	ecx,esi
		mov	esi,[ebx+Attribute.begin]
		sub	ecx,esi	; length of first part
;[c]		
;[c]Pre-reserve sufficient space
;[c]		
		mov	edi,[ebp+ParseContext.base]
		lea	edx,[edi+ecx]
		cmp	edx,[ebp+ParseContext.limit]
		jae	.chunkFull
.resume:	mov	[ebx+Attribute.begin],edi
;[c]
;[c]Copy first part
;[c]
		rep movsb
;[c]
;[c]Copy remaining chars
;[c]
;[c]	Note: it is no longer to check for unexpected end in this loop since
;[c]	we have already scanned the value while counting chars.
;[c]		
		mov	ecx,[ebp+ParseContext.limit]
		sub	ecx,edi
		jmp	.decodeContent

.decode:	call	decodeReference
.loop:		stosb
		sub	ecx,1
		jz	.realloc1
.decodeContent:	movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'&'
		jz	.decode
		cmp	al,'<'
		jnz	.loop
		movzx	eax,byte [esi]
		cmp	al,'!'
		jz	.CDATAOrComment
		cmp	al,'?'
		jz	.PI

		mov	[ebx+Attribute.limit],edi
;[c]		
;[c]Free remaining space (align on the next dword)
;[c]
		add	edi,3
		and	edi,not 3
		mov	[ebp+ParseContext.base],edi
		pop	edi
		pop	edx
		pop	ecx

		; Terminate this attribute and go to the next one
		movzx	eax,byte [esi]
		ret
;[c]
.chunkFull:	push	ecx
		lea	eax,[ecx+1] ; at least one extra char
		call	extendMemory
		pop	ecx
		jnz	.outOfMemory
		jmp	.resume
;[c]
.realloc1:	call	.realloc
		jmp	.decodeContent
;[c]
.realloc:	mov	eax,edi
		sub	eax,[ebx+Attribute.begin]
		add	eax,[ebp+MemoryContext.chunkSize]
		add	eax,3
		and	eax,not 3
		push	edi
		call	extendMemory
		pop	ecx
		jnz	.outOfMemory1

		push	esi
		mov	esi,[ebx+Attribute.begin]
		mov	[ebx+Attribute.begin],edi
		sub	ecx,esi
		rep movsb
		add	esi,1
		mov	ecx,[ebp+ParseContext.limit]
		sub	ecx,edi
		pop	esi		
		ret
;[c]
.outOfMemory1:	add	esp,4
.outOfMemory:	pop	edi
		pop	edx
		pop	ecx
		add	esp,4
		jmp	parseOutOfMemory
;[c]
.unexpectedEnd:	pop	edi
		pop	edx
		pop	ecx
		add	esp,4
		jmp	unexpectedEnd
;[c]
.invalidChar:	pop	edi
		pop	edx
		pop	ecx
		add	esp,4
		jmp	invalidChar
;[c]
.error:		pop	edi
		pop	edx
		pop	ecx
		add	esp,4
		or	eax,eax
		ret
;[c]
.CDATAOrComment:
		add	esi,1
		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'-'
		jz	.comment

;[of]:Read CDATA Section
		cmp	al,'['
		jnz	.invalidChar
		cmp	byte [esi],'C'
		jnz	.invalidChar
		cmp	byte [esi+1],'D'
		jnz	.invalidChar
		cmp	byte [esi+2],'A'
		jnz	.invalidChar
		cmp	byte [esi+3],'T'
		jnz	.invalidChar
		cmp	byte [esi+4],'A'
		jnz	.invalidChar
		cmp	byte [esi+5],'['
		jnz	.invalidChar
		add	esi,6

		jmp	.cd2
.cd1:		stosb
		sub	ecx,1
		jz	.cd3		; chunk is full - realloc
.cd2:		movzx	eax,byte [esi]
		add	esi,1
		or	al,al
		jz	.unexpectedEnd
		cmp	al,']'
		jnz	.cd1
		movzx	eax,byte [esi]
		cmp	al,']'
		jnz	.cd1
		mov	al,[esi+1]
		cmp	al,'>'
		jnz	.cd1
		add	esi,2
		jmp	.decodeContent

.cd3:		call	.realloc
		jmp	.cd2
;[cf]
;[of]:Skip Comments
.comment:	call	readComment
		jnz	.error
		jmp	.decodeContent
;[cf]
;[of]:Skip PI
.PI:		call	readPI
		jnz	.error
		jmp	.decodeContent
;[cf]
;[cf]
;[of]:	decodeReference
decodeReference:
		movzx	eax,byte [esi]
		cmp	al,'#'
		jz	.num
		cmp	al,'a'
		jz	.a
		cmp	al,'l'
		jz	.l
		cmp	al,'g'
		jz	.g
		cmp	al,'q'
		jnz	.invalidEntityReference

		; &quot;
.q:		cmp	byte [esi+1],'u'
		jnz	.invalidEntityReference
		cmp	byte [esi+2],'o'
		jnz	.invalidEntityReference
		cmp	byte [esi+3],'t'
		jnz	.invalidEntityReference
		cmp	byte [esi+4],';'
		jnz	.invalidEntityReference
		add	esi,5
		mov	al,'"'
		ret

.num:		add	esi,1
		xor	edx,edx
		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'x'
		jz	.hexa
		test	byte [digit+eax],1
		jz	.invalidChar
.nextDigit:	sub	al,'0'
		imul	edx,10
		jc	.overflow
		add	edx,eax		
		jc	.overflow
		movzx	eax,byte [esi]
		add	esi,1
		test	byte [digit+eax],1
		jnz	.nextDigit
		cmp	al,';'
		jnz	.invalidEntityReference
		mov	eax,edx
		test	edx,$FFFFFF00
		jnz	.invalidChar
		ret

.hexa:		movzx	eax,byte [esi]
		add	esi,1
		test	byte [digit+eax],2
		jz	.invalidChar
.nextXDigit:	shl	edx,4
		jc	.overflow
		or	dl,[xdigit+eax]
		movzx	eax,byte [esi]
		add	esi,1
		test	byte [digit+eax],2
		jnz	.nextXDigit
		cmp	al,';'
		jnz	.invalidEntityReference
		mov	eax,edx
		test	edx,$FFFFFF00
		jnz	.invalidChar
		ret
		
.a:		mov	al,[esi+1]
		cmp	al,'p'
		jz	.ap
		cmp	al,'m'
		jnz	.invalidEntityReference

		; &amp;
.am:		cmp	byte [esi+2],'p'
		jnz	.invalidEntityReference
		cmp	byte [esi+3],';'
		jnz	.invalidEntityReference
		add	esi,4
		mov	al,'&'
		ret

		; &apos;
.ap:		cmp	byte [esi+2],'o'
		jnz	.invalidEntityReference
		cmp	byte [esi+3],'s'
		jnz	.invalidEntityReference
		cmp	byte [esi+4],';'
		jnz	.invalidEntityReference
		add	esi,5
		mov	al,$27
		ret

		; &lt;
.l:		cmp	byte [esi+1],'t'
		jnz	.invalidEntityReference
		cmp	byte [esi+2],';'
		jnz	.invalidEntityReference
		add	esi,3
		mov	al,'<'
		ret

		; &gt;
.g:		cmp	byte [esi+1],'t'
		jnz	.invalidEntityReference
		cmp	byte [esi+2],';'
		jnz	.invalidEntityReference
		add	esi,3
		mov	al,'>'
		ret
;[c]
.invalidChar:	add	esp,4
		pop	edi
		pop	edx
		pop	ecx
		jmp	invalidChar
;[c]
.overflow:	add	esp,4
		pop	edi
		pop	edx
		pop	ecx
		jmp	overflow
;[c]
.invalidEntityReference:
		add	esp,4
		pop	edi
		pop	edx
		pop	ecx
		jmp	invalidEntityReference
;[cf]
;[of]:	readProlog
;[c]Read the prolog
;[c]
;[c]	The time is not critical here, so the code is less optimized:
;[c]	- use of subfunctions
;[c]	- return error code (instead of direct exit)
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		source
;[c]
;[c]RETURN VALUES
;[c]	zf+eax
;[c]		error code (zf=0) or current char (zf=1)
;[c]	esi
;[c]		next source char
;[c]
readProlog:	call	readXMLDecl
		jnz	return
		jmp	readMisc
;[cf]
;[of]:	readXMLDecl
;[c]Read the XML declaration
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		next char to read
;[c]
;[c]RETURN VALUES
;[c]	zf+eax
;[c]		error code
;[c]	esi
;[c]		next char to read
;[c]
;[c]REMARKS
;[c]	If there is no xml-decl, the function just returns the same pointer
;[c]	and the ok flag.
;[c]

		struct XDA
.value		rd	2
		ends

readXMLDecl:	push	edi
		sub	esp,XDA.sizeof
		mov	edi,esp
		call	.goon
		lea	esp,[esp+XDA.sizeof]
		pop	edi
		ret

.goon:		cmp	byte [esi],'<'
		jnz	ok
		cmp	byte [esi+1],'?'
		jnz	ok
		cmp	byte [esi+2],'x'
		jnz	ok
		cmp	byte [esi+3],'m'
		jnz	ok
		cmp	byte [esi+4],'l'
		jnz	ok
		add	esi,5

		; Read version
		; ------------
		call	readNextChar
		call	readBlanks
		jnz	return
		call	readAtom
		jnz	return
		cmp	ecx,ATOM_VERSION
		jnz	noVersion
		
		call	readXMLDeclValue
		jnz	return

		mov	ecx,[edi+XDA.value+Attribute.begin]
		mov	[ebp+ParseContext.version+Attribute.begin],ecx
		mov	ecx,[edi+XDA.value+Attribute.limit]
		mov	[ebp+ParseContext.version+Attribute.limit],ecx
		
		; Read encoding
		; -------------
		call	isXMLDeclEnd
		jz	ok
		call	readBlanks
		jnz	return
		call	isXMLDeclEnd
		jz	return
		call	readAtom
		jnz	return
		cmp	ecx,ATOM_ENCODING
		jnz	.notEncoding
		
		call	readXMLDeclValue
		jnz	return

		mov	ecx,[edi+XDA.value+Attribute.begin]
		mov	[ebp+ParseContext.encoding+Attribute.begin],ecx
		mov	ecx,[edi+XDA.value+Attribute.limit]
		mov	[ebp+ParseContext.encoding+Attribute.limit],ecx

		; Read standalone
		; ---------------
		call	isXMLDeclEnd
		jz	ok
		call	readBlanks
		jnz	return
		call	isXMLDeclEnd
		jz	ok
		call	readAtom
		jnz	return
.notEncoding:	cmp	ecx,ATOM_STANDALONE
		jnz	invalidChar
		
		call	readXMLDeclValue
		jnz	return

		; Terminate
		; ---------
		call	isXMLDeclEnd
		jz	ok
		jmp	invalidChar

;[of]:readXMLDeclValue
readXMLDeclValue:

		; Skip blanks
		; -----------
		call	skipBlanks

		; Skip equals
		; -----------
		cmp	al,'='
		jnz	invalidChar
		call	readNextChar
		
		; Skip blanks
		; -----------
		call	skipBlanks

		; Skip quote
		; ----------
		cmp	al,$27	; '
		jz	.value
		cmp	al,'"'
		jnz	invalidChar
.value:		mov	cl,al
		mov	[edi+XDA.value+Attribute.begin],esi

.loopValue:	movzx	eax,byte [esi]
		add	esi,1
		or	al,al
		jz	unexpectedEnd
		cmp	al,' '		; Let's forbid blanks
		jz	invalidChar	;
		cmp	al,cl
		jnz	.loopValue
		lea	ecx,[esi-1]
		mov	[edi+XDA.value+Attribute.limit],ecx
		
		jmp	readNextChar
;[cf]
;[of]:isXMLDeclEnd
isXMLDeclEnd:	cmp	al,'?'
		jnz	return
		cmp	byte [esi],'>'
		jnz	return
		lea	esi,[esi+1]
		ret
;[cf]
;[cf]
;[of]:	readMisc
;[c]Read stuff before or after the root element
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		next char to read
;[c]
;[c]RETURN VALUES
;[c]	zf+eax
;[c]		error code (zf=0) or current char (zf=1)
;[c]	esi
;[c]		next char to read
;[c]
readMisc:
		; Skip blanks
.sb:		movzx	eax,byte [esi]
		add	esi,1
		test	byte [S + eax], 1
		jnz	.sb
		
		cmp	al,'<'
		jnz	.done

		cmp	byte [esi],'?'
		jnz	.notPI

		call	readPI
		jmp	.next

.notPI:		cmp	byte [esi],'!'
		jnz	.done
		add	esi,1

		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'-'
		jnz	.notComment

		call	readComment
		jmp	.next
		
.notComment:	call	readDOCTYPE

.next:		jnz	return
		jmp	.sb

.done:		test	eax,0
		ret
;[cf]
;[of]:	readComment
;[c]Read a comment
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		points to the 2nd '-' of <!--
;[c]
;[c]RETURN VALUES
;[c]	zf+eax
;[c]		error code
;[c]	esi
;[c]		next char to read
;[c]
;[c]
readComment:	cmp	byte [esi],'-'
		jnz	invalidChar
		add	esi,1

.loop:		movzx	eax,byte [esi]
		add	esi,1
		or	al,al
		jz	unexpectedEnd
		cmp	al,'-'
		jnz	.loop
		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'-'
		jnz	.loop
		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'>'
		jnz	invalidChar

		xor	eax,eax
		ret
;[cf]
;[of]:	readPI
;[c]Reads a Processing Instruction
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		points to the '?'
;[c]
;[c]RETURN VALUES
;[c]	zf+eax
;[c]		error code
;[c]	esi
;[c]		next char to read
;[c]
readPI:		add	esi,1

		mov	ecx,esi
		movzx	eax,byte [esi]
		add	esi,1
		call	readName
		jnz	return
;[c]
;[c]	The PI target cannot be 'xml' in any case
;[c]
		cmp	byte [ecx],'x'
		jz	.m
		cmp	byte [ecx],'X'
		jnz	.notXML
.m:		cmp	byte [ecx+1],'m'
		jz	.l
		cmp	byte [ecx+1],'M'
		jnz	.notXML
.l:		cmp	byte [ecx+2],'l'
		jz	.xml
		cmp	byte [ecx+2],'L'
		jnz	.notXML
.xml:		add	ecx,4
		cmp	esi,ecx
		jz	invalidPI
;[c]
;[c]	If there is no blank, it MUST be the end of the PI
;[c]
.notXML:	cmp	al,'?'
		jnz	.notEnd
		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'>'
		jz	.ok
		jmp	invalidChar
;[c]
;[c]	It is not the end: there must be at least one blank
;[c]		
.notEnd:	call	readBlanks
		jnz	return
		jmp	.next
;[c]
;[c]	Read the content of the Processing Instruction
;[c]
.loop:		movzx	eax,byte [esi]
		add	esi,1
.next:		or	al,al
		jz	unexpectedEnd
		cmp	al,'?'
		jnz	.loop
		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'>'
		jnz	.next

.ok:		xor	eax,eax
		ret
;[cf]
;[of]:	readDOCTYPE
readDOCTYPE:	call 	readAtom
		jnz	return
		call	readBlanks
		jnz	return

		cmp	ecx,ATOM_DOCTYPE
		jnz	invalidChar
		cmp	[ebp+ParseContext.doctype],1
		jnz	invalidDOCTYPE
		mov	[ebp+ParseContext.doctype],0

		call	readName
		jnz	return
		
		call	skipBlanks
		call	readExternalID
		jnz	return
		call	skipBlanks

		; ('[' intSubset ']')?
		cmp	al,'['
		jnz	.notIntSubset
		call	readIntSubset
		cmp	al,']'
		jnz	invalidChar
		
		movzx	eax,byte [esi]
		add	esi,1
		call	skipBlanks

.notIntSubset:	cmp	al,'>'
		jnz	invalidChar
		xor	eax,eax
		ret
;[c]
;[c]Sub-functions
;[of]:	readNmtoken
readNmtoken:	jmp	readName
;[cf]
;[of]:	readExternalID
readExternalID:
		; SYSTEM
		cmp	al,'S'
		jz	readSystem

		; PUBLIC		
		cmp	al,'P'
		jz	readPublic

		jmp	ok
;[cf]
;[of]:	readSystem
readSystem:	cmp	byte [esi],'Y'
		jnz	invalidChar
		cmp	byte [esi+1],'S'
		jnz	invalidChar
		cmp	byte [esi+2],'T'
		jnz	invalidChar
		cmp	byte [esi+3],'E'
		jnz	invalidChar
		cmp	byte [esi+4],'M'
		jnz	invalidChar
		add	esi,5
		
		call	readNextChar
		call	readBlanks
		jnz	return
		jmp	readString
;[cf]
;[of]:	readPublic
readPublic:	cmp	byte [esi],'U'
		jnz	invalidChar
		cmp	byte [esi+1],'B'
		jnz	invalidChar
		cmp	byte [esi+2],'L'
		jnz	invalidChar
		cmp	byte [esi+3],'I'
		jnz	invalidChar
		cmp	byte [esi+4],'C'
		jnz	invalidChar
		add	esi,5

		call	readNextChar
		call	readBlanks
		jnz	return
		call	readPubidLiteral
		jnz	return

		; Not a blank: there is no SystemLiteral
		test	byte [S + eax], 1
		jz	ok

		call	skipBlanks
		cmp	al,$27	; '
		jz	readString
		cmp	al,'"'
		jz	readString
		jmp	ok
		
;[cf]
;[of]:	readPubidLiteral
readPubidLiteral:
		mov	cl,al
		cmp	al,$27	; '
		jz	.loop
		cmp	al,'"'
		jnz	invalidChar
.loop:		movzx	eax,byte [esi]
		add	esi,1
		or	al,al
		jz	unexpectedEnd
		cmp	byte [PubidChar+eax],1
		jnz	invalidChar
		cmp	al,cl
		jnz	.loop
		jmp	readNextChar
;[cf]
;[of]:	readString
readString:	mov	cl,al
		cmp	al,$27	; '
		jz	.loop
		cmp	al,'"'
		jnz	invalidChar
.loop:		mov	al,[esi]
		add	esi,1
		or	al,al
		jz	unexpectedEnd
		cmp	al,cl
		jnz	.loop
		jmp	readNextChar
;[cf]
;[of]:	readIntSubset
readIntSubset:

		; Skip blanks
.loop:		movzx	eax,byte [esi]
		add	esi,1

.first:		test	byte [S + eax], 1
		jnz	.loop

		cmp	al,'%'
		jnz	.notPERef
		call	readPERef
		jmp	.next
	
.notPERef:	cmp	al,'<'
		jnz	ok

		cmp	byte [esi],'?'
		jnz	.notPI
		call	readPI
		jmp	.next

.notPI:		cmp	byte [esi],'!'
		jnz	ok
		add	esi,1

		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,'-'
		jnz	.notComment
		call	readComment
		jmp	.next
		
.notComment:	call	readDecl

.next:		jz	.loop
		ret
;[cf]
;[of]:	readPERef
readPERef:	call	readNextChar
		call	readName
		jnz	return
		cmp	al,';'
		jnz	invalidChar
		jmp	ok
;[cf]
;[of]:	readDecl
readDecl:	call 	readAtom
		jnz	return
		call	readBlanks
		jnz	return
		
		cmp	ecx,ATOM_ELEMENT
		jz	.element
		cmp	ecx,ATOM_ATTLIST
		jz	.attlist
		cmp	ecx,ATOM_ENTITY
		jz	.entity
		cmp	ecx,ATOM_NOTATION
		jz	.notation
		jmp	invalidChar
;[c]
.element:	call	readName
		jnz	return
		call	readBlanks
		jnz	return
		call	readContentSpec
		jmp	.common
;[c]
.attlist:	call	readName
		jnz	return
		call	readAttDefs
		jmp	.common
;[c]
.entity:	cmp	al,'%'
		jnz	.notPE

		call	readNextChar
		call	readBlanks
		jnz	return
		call	readName
		jnz	return
		call	readBlanks
		jnz	return
		call	readPEDef
		jmp	.common
		
.notPE:		call	readName
		jnz	return
		call	readBlanks
		jnz	return
		call	readEntityDef
		jmp	.common
;[c]
.notation:	call	readName
		jnz	return
		call	readBlanks
		jnz	return
		call	readExternalID

.common:	jnz	return
		call	skipBlanks
		cmp	al,'>'
		jnz	invalidChar
		jmp	ok
;[cf]
;[of]:	readAttDefs
readAttDefs:
.loop:		; Not a blank: the list is terminated
		test	byte [S + eax], 1
		jz	ok

		call	skipBlanks

		; Not a name: the list is terminated
		cmp	byte [terminalChar+eax],1
		jnz	ok

		call	readName
		jnz	return
		call	readBlanks
		jnz	return
		call	readAttType
		jnz	return
		call	readBlanks
		jnz	return
		call	readDefaultDecl		
		jnz	return
		
		jmp	.loop
;[cf]
;[of]:	readAttType
readAttType:	cmp	al,'('
		jz	.list

		call	readAtom
		jnz	return

		cmp	ecx,ATOM_CDATA
		jc	invalidChar
		cmp	ecx,ATOM_NOTATION + 1
		jnc	invalidChar

		cmp	ecx,ATOM_NOTATION
		jnz	ok
;[c]
;[c]	'NOTATION' S '(' S? Name (S? '|' S? Name)* S? ')'
;[c]		
		call	readBlanks
		jnz	return
		cmp	al,'('
		jnz	invalidChar

.loop:		call	readNextChar
		call	skipBlanks
		call	readName
		jnz	return
		call	skipBlanks
		cmp	al,'|'
		jz	.loop
		
		jmp	.common
;[c]
;[c]	'(' S? Nmtoken (S? '|' S? Nmtoken)* S? ')'
;[c]
.list:		call	readNextChar
		call	skipBlanks
		call	readNmtoken
		jnz	return
		call	skipBlanks
		cmp	al,'|'
		jz	.list
		
.common:	or	al,al
		jz	unexpectedEnd
		cmp	al,')'
		jnz	invalidChar
		jmp	readNextChar
;[cf]
;[of]:	readDefaultDecl
readDefaultDecl:
		cmp	al,'#'
		jnz	readAttValue
		call	readNextChar
		call	readAtom
		jnz	return
		cmp	ecx,ATOM_IMPLIED
		jz	ok
		cmp	ecx,ATOM_REQUIRED
		jz	ok
		cmp	ecx,ATOM_FIXED
		jnz	invalidChar
		
		call	readBlanks
		jnz	return
		jmp	readAttValue
;[cf]
;[of]:	readEntityDef
readEntityDef:	cmp	al,$27	; '
		jz	readEntityValue
		cmp	al,'"'
		jz	readEntityValue
		
		call	readExternalID
		jnz	return
		
		; if the next char is not a blank: it can't be a NDATA
		test	byte [S + eax],1
		jz	ok

		call	skipBlanks
		call	readAtom
		jnz	return
		cmp	ecx,ATOM_NDATA
		jnz	ok
		call	readBlanks
		jnz	return
		jmp	readName
;[cf]
;[of]:	readPEDef
readPEDef:	cmp	al,$27	; '
		jz	readEntityValue
		cmp	al,'"'
		jz	readEntityValue
		jmp	readExternalID
;[cf]

;[of]:	readContentSpec
readContentSpec:
		;
		; Name Cardinality
		;
		cmp	byte [terminalChar+eax],1
		jnz	.notName
		call	readName
		jnz	return
		jmp	readCardinality
		
		;
		; #PCDATA
		;
.notName:	cmp	al,'#'
		jnz	.notPCDATA
		call	readNextChar
		call	readAtom
		jnz	return
		cmp	ecx,ATOM_PCDATA
		jnz	invalidChar
		jmp	ok

		;
		; Group
		;		
.notPCDATA:	cmp	al,'('
		jnz	ok

.next:		movzx	eax,byte [esi]
		add	esi,1
		call	skipBlanks
		call	readContentSpec
		jnz	return
		call	skipBlanks
		
		cmp	al,'|'
		jz	.next
		cmp	al,','
		jz	.next
		cmp	al,')'
		jnz	invalidChar
		call	readNextChar
		jmp	readCardinality
;[cf]
;[of]:	readCardinality
readCardinality:
		cmp	al,'+'
		jz	readNextChar
		cmp	al,'?'
		jz	readNextChar
		cmp	al,'*'
		jz	readNextChar
		jmp	ok
;[cf]
;[of]:	readEntityValue
readEntityValue:
		jmp	readAttValue
;[cf]
;[of]:	readAttValue
readAttValue:	cmp	al,$27	; '
		jz	.value
		cmp	al,'"'
		jnz	invalidChar
.value:		mov	cl,al
.loop:		mov	al,[esi]
		add	esi,1
		;cmp	al,'<'		; readEntityValue accepts '<'
		;jz	invalidChar
		or	al,al
		jz	unexpectedEnd
		cmp	al,cl
		jnz	.loop
		jmp	readNextChar
;[cf]
;[cf]

;[of]:	readAtom
;[c]Read an atom
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		current char
;[c]	esi
;[c]		next char to read
;[c]
;[c]RETURN VALUES
;[c]	zf+eax
;[c]		error code (zf=0) or first non blank char following atom
;[c]	esi
;[c]		next char to read
;[c]	ecx
;[c]		the atom id or -1 if not found
;[c]
readAtom:	push	ebx
		push	edx
		push	edi

		;
		; Read the atom name
		;
		lea	ebx,[esi-1]	; beginning of the atom
		jmp	.first
.loop:		mov	al,[esi]
		add	esi,1
.first:		cmp	al,'A'
		jc	.endOfAtom
		cmp	al,'Z'+1
		jc	.loop
		cmp	al,'a'
		jc	.endOfAtom
		cmp	al,'z'+1
		jc	.loop
.endOfAtom:	lea	edx,[esi-1]	; end of the atom

		;
		; Find the atom in the table
		;
		push	esi
		
		cmp	ebx,edx
		jz	.noMatch

		sub	ecx,ecx		; the atom
		dec	ecx
.compareAtom:	inc	ecx
		mov	edi,[atomTable+ecx*4]
		or	edi,edi
		jz	.noMatch
		mov	esi,ebx
.compare:	cmpsb
		jnz	.compareAtom
		cmp	esi,edx
		jnz	.compare
		cmp	byte [edi], 0
		jnz	.compareAtom

.done:		pop	esi
		pop	edi
		pop	edx
		pop	ebx
		test	eax,0
		ret
		
.noMatch:	sub	ecx,ecx
		dec	ecx
		jmp	.done
;[cf]
;[of]:	readName
readName:	
		; there must be at least one char
		cmp	byte [terminalChar+eax],1
		jnz	invalidChar

.loop:		movzx	eax,byte [esi]
		add	esi,1
		cmp	byte [terminalChar+eax],1
		jz	.loop
		test	eax,0
		ret
;[cf]
;[of]:	readNextChar
readNextChar:	movzx	eax,byte [esi]
		add	esi,1
		jmp	ok
;[cf]
;[of]:	readBlanks
;[c]There must be at least one blank	
;[c]
readBlanks:	test	byte [S + eax], 1
		jz	invalidChar

		movzx	eax,byte [esi]
		add	esi,1
		call	skipBlanks
		test	eax,0
		ret
;[cf]
;[of]:	skipBlanks
;[c]Skip blanks
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		the current char
;[c]	esi
;[c]		the address of the next char
;[c]
;[c]RETURN VALUES
;[c]	eax
;[c]		the first non blank char
;[c]	esi
;[c]		the address of the next char
;[c]
skipBlanks:	test	byte [S + eax], 1
		jz	.done
.loop:		movzx	eax,byte [esi]
		add	esi,1
		test	byte [S + eax], 1
		jnz	.loop
.done:		ret
;[cf]
;[c]
;[c]Recoverable Errors...	
;[c]
;[of]:	parseChunkFull
parseChunkFull:	push	ecx
		push	edx
		mov	eax,[edx+ElementClass.size]
		call	extendMemory
		pop	edx
		pop	ecx
		jz	resumeParseChunkFull
		ret
;[cf]
;[of]:	invalidAttribute
invalidAttribute:
		cmp	[ebp+ParseContext.strict],0
		jnz	.invalid

		; We are in a non-strict mode, this
		; unknown attribute must just be ignored, so
		; we read all chars until the first '=' char
		; no matter whether the char is valid or not.
		;
		jmp	.first
.loop:		movzx	eax,byte [esi]
		add	esi,1
.first:		or	al,al
		jz	unexpectedEnd
		cmp	al,'='
		jnz	.loop

		; set offset to the 'ignored' slot and resume
		; reading the attribute's value.
		;
		mov	ebx,edi
		add	ebx,Element.reserved
		jmp	readAttributeValue

.invalid:	mov	eax,RC_INVALID_ATTRIBUTE
		or	eax,eax
		ret
;[cf]
;[of]:	invalidElement
invalidElement:	cmp	[ebp+ParseContext.strict],0
		jnz	invalidChar

		; We are in a non-strict mode, this
		; unknown attribute must just be ignored, so
		; we read all chars until the first '=' char
		; no matter whether the char is valid or not.
		;
		jmp	.first
.loop:		movzx	eax,byte [esi]
		add	esi,1
.first:		or	al,al
		jz	unexpectedEnd
		cmp	byte [terminalChar+eax],1
		jz	.loop

;[of]:Skip Blanks
		test	byte [S + eax], 1
		jz	.eNotBlank1
.eSkipBlank1:	movzx	eax,byte [esi]
		add	esi,1
		test	byte [S + eax], 1
		jnz	.eSkipBlank1
.eNotBlank1:
;[cf]

		; Read content using the invalid class and invalid element
		push	edx
		push	edi
		mov	edx,invalidClass	
		lea	edi,[ebp+ParseContext.invalidElement]
		call	readAttributes
		pop	edi
		pop	edx
		jz	readContent
		ret
;[cf]
;[of]:	closeTagMismatch
closeTagMismatch:
		cmp	[ebp+ParseContext.strict],0
		jnz	tagMismatch

		; We are in a non-strict mode, this
		; unknown attribute must just be ignored, so
		; we read all chars until the first '>' char
		; no matter whether the char is valid or not.
		;
.loop:		movzx	eax,byte [esi]
		add	esi,1
		or	al,al
		jz	unexpectedEnd
		cmp	al, '>'
		jnz	.loop

		xor	eax,eax		; element successfully read
		ret
;[cf]
;[c]
;[c]Errors...
;[c]
;[of]:	ok
ok:		test	eax,0
return:		ret
;[cf]
;[of]:	invalidEntityReference
invalidEntityReference:
		mov	eax,RC_INVALID_ENTITY_REFERENCE
		or	eax,eax
		ret
;[cf]
;[of]:	unexpectedEnd
unexpectedEnd:	mov	eax,RC_UNEXPECTED_END
		or	eax,eax
		ret
;[cf]
;[of]:	invalidChar
invalidChar:	mov	eax,RC_INVALID_CHAR
		or	eax,eax
		ret
;[cf]
;[of]:	invalidPI
invalidPI:	mov	eax,RC_INVALID_PI
		or	eax,eax
		ret
;[cf]
;[of]:	overflow
overflow:	mov	eax,RC_OVERFLOW
		or	eax,eax
		ret
;[cf]
;[of]:	notStartTag
notStartTag:	mov	eax,RC_NO_START_TAG
		or	eax,eax
		ret
;[cf]
;[of]:	tagMismatch
tagMismatch:	mov	eax,RC_TAG_MISMATCH
		or	eax,eax
		ret
;[cf]
;[of]:	invalidTag
invalidTag:	mov	eax,RC_INVALID_TAG
		or	eax,eax
		ret
;[cf]
;[of]:	parseOutOfMemory
parseOutOfMemory:
		mov	eax,RC_MEMORY
		or	eax,eax
		ret
;[cf]
;[of]:	attributeDefined
attributeDefined:
		mov	eax,RC_ATTR_DEFINED
		or	eax,eax
		ret
;[cf]
;[of]:	elementDefined
elementDefined:
		mov	eax,RC_ELEM_DEFINED
		or	eax,eax
		ret
;[cf]
;[of]:	invalidDOCTYPE
invalidDOCTYPE:
		mov	eax,RC_INVALID_DOCTYPE
		or	eax,eax
		ret
;[cf]
;[of]:	noVersion
noVersion:	mov	eax,RC_VERSION_EXPECTED
		or	eax,eax
		ret
;[cf]
;[cf]
;[of]:computeLineColumn
;[c]Read the text file again nd setup line and column
;[c]
;[c]	It is faster to count lines only when an error occurs. So the parsing
;[c]	routine does not compute lines and if an error occurs, the file is
;[c]	read again just to find the line and column of the last read byte.
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		the position of the last read byte
;[c]	ebp
;[c]		the parse context
;[c]
;[c]RETURN VALUES
;[c]	[ebp+ParseContext.line]
;[c]		the line
;[c]	[ebp+ParseContext.column]
;[c]		the column
;[c]	
computeLineColumn:
		push	ebx
		push	esi
		push	edi

		mov	edi,esi
		mov	esi,[ebp+ParseContext.source]
		mov	ecx,1	; line number
		mov	edx,esi	; beginning of line
		cmp	esi,edi
		jz	.continue

.loop1:		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,13
		jz	.CR
		cmp	al,10
		jz	.LF
.next:		cmp	esi,edi
		jnz	.loop1
		jmp	.continue
				
.CR:		cmp	esi,edi
		jz	.LF
		cmp	byte [esi],10
		jnz	.LF
		add	esi,1
.LF:		add	ecx,1
		mov	edx,esi
		jmp	.next

.continue:	mov	[ebp+ParseContext.line],ecx

		;
		; Compute column by expanding tabs
		;
		
		mov	esi,edx
		xor	ecx,ecx		; column
		mov	edx,TAB_SIZE	; next tab
		cmp	esi,edi
		jz	.continue2
.loop2:		movzx	eax,byte [esi]
		add	esi,1
		cmp	al,9
		jnz	.notTab
		mov	ecx,edx
		add	edx,TAB_SIZE
		cmp	esi,edi
		jnz	.loop2
		jmp	.continue2
.notTab:	add	ecx,1
		cmp	esi,edi
		jnz	.loop2

.continue2:	inc	ecx
		mov	[ebp+ParseContext.column],ecx

		pop	edi
		pop	esi
		pop	ebx
		ret
;[cf]

;[of]:initializeClassParser
;[c]Initialize the class parser
;[c]
;[c]ARGUMENTS
;[c]	ebp
;[c]		the parse context
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]
initializeClassParser:
		mov	eax,DEFAULT_CHUNK_SIZE
		xor	ecx,ecx
		mov	[ebp+ParseContext.chunkSize],eax
		mov	[ebp+ParseContext.chunks],ecx
		jmp	newChunk
;[cf]
;[of]:releaseClassParser
;[c]Release the class parser
;[c]
;[c]ARGUMENTS
;[c]	ebp
;[c]		the class parser
;[c]
releaseClassParser:
		jmp	releaseChunks
;[cf]
;[of]:classFromString
;[c]Create a class from a string
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		the xml string describing the class
;[c]	ebp
;[c]		the class context.
;[c]
;[c]RETURN VALUE
;[c]	eax+zf
;[c]		error code
;[c]
classFromString:
		push	esi
		push	edi
		push	ebp
		mov	edi,ebp
		
		sub	esp,ParseContext.sizeof
		mov	ebp,esp
		mov	ecx,16384
		call	initializeParser
		jnz	.error

		mov	edx,SchemaClass
		push	edi
		call	parse
		pop	edi
		jz	.ok

		push	eax
		call	computeLineColumn
		pop	eax
		mov	ecx,[ebp+ParseContext.line]
		mov	edx,[ebp+ParseContext.column]
		mov	[edi+CreateClassContext.line],ecx
		mov	[edi+CreateClassContext.column],edx
		jmp	.error2

.ok:		mov	esi,[ebp+ParseContext.root]
		mov	ebp,edi
		call	classFromElement
		mov	ebp,esp
	
.error2:	push	eax
		call	releaseParser
		pop	eax

.error:		add	esp,ParseContext.sizeof
		or	eax,eax
		pop	ebp
		pop	edi
		pop	esi
		ret
;[cf]
;[of]:classFromElement
;[c]Create a class from an element
;[c]
;[c]ARGUMENTS
;[c]	ebp
;[c]		the create class context
;[c]	esi
;[c]		root element
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]
classFromElement:
		push	ebx
		push	esi
		push	edi
		mov	[ebp+CreateClassContext.rootElement],esi
		
		;
		; Declare all global classes
		;
		mov	eax,esi
		call	declareGlobalClasses
		jnz	.error

		;
		; Define all global classes
		;
		mov	esi,[esi+Element.firstChild]
		mov	edx,[ebp+CreateClassContext.classes]
		mov	ebx,ebp
		jmp	.first
.loop:		mov	edi,[edx]
		add	edx,4
		push	edx
		call	initializeClass
		pop	edx
		jnz	.error
		mov	esi,[esi+Element.nextSibling]
.first:		or	esi,esi
		jnz	.loop

.error:		pop	edi
		pop	esi
		pop	ebx
		ret
;[c]
;[c]SUB-FUNCTIONS
;[of]:	declareGlobalClasses
;[c]Create the list of global classes
;[c]
;[c]	Create a class for each <collection> under the root
;[c]	
;[c]ARGUMENTS
;[c]	eax
;[c]		the schema element
;[c]	ebp
;[c]		the context
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]	ebx
;[c]		the root source element
;[c]	ecx
;[c]		the root element class
;[c]
declareGlobalClasses:
		push	esi
		push	edi
		mov	esi,eax
		
		;
		; Create an array to store all classes
		;
		call	countGlobals
		inc	eax
		shl	eax,2
		mov	ecx,4
		mov	edx,ebp
		call	allocateMemory
		jnz	.error
		mov	[ebp+CreateClassContext.classes],edi

		xor	eax,eax
		mov	[ebp+CreateClassContext.rootClass],eax

		;
		; Enumerate all the collection element
		; under the root element.
		;
		mov	esi,[esi+Element.firstChild]
		jmp	.first
.loop:				; Create the class
		mov	eax,esi
		xor	ebx,ebx
		cmp	[esi+Element.id],elementId
		jnz	.notElement
		inc	ebx
.notElement:	mov	ecx,ebp
		call	newElementClass
		jnz	.error
		
		; Add it to the list
		mov	eax,ebx
		stosd
		
		; Save the source element to the class
		; (for forward references)
		mov	[ebx+ElementClass.source],esi

		; Mark the collection/element as shared
		mov	[ebx+ElementClass.shared],1

		cmp	[esi+Element.id],documentId
		jnz	.notDocument
		cmp	[ebp+CreateClassContext.rootClass],0
		jnz	.dupDocument
		mov	[ebp+CreateClassContext.rootClass],eax
.notDocument:

		mov	esi,[esi+Element.nextSibling]
.first:		or	esi,esi
		jnz	.loop

		;
		; Check that the schema contains one document
		;
		mov	eax,[ebp+CreateClassContext.rootClass]
		or	eax,eax
		jz	.schemaEmpty

		; Terminate the list with a null
		xor	eax,eax
		stosd

		xor	eax,eax
.error:		pop	edi
		pop	esi
		ret
;[c]
.schemaEmpty:	mov	eax,RC_SCHEMA_EMPTY
		or	eax,eax
		jmp	.error
;[c]
.dupDocument:	mov	eax,RC_DOCUMENT_DEFINED
		or	eax,eax
		jmp	.error
;[c]
;[c]SUB-FUNCTIONS
;[of]:	countGlobals
;[c]Count number of child classes of type collection
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		the element
;[c]
;[c]RETURN VALUES
;[c]	eax
;[c]		the number of child classes
;[c]
countGlobals:	push	esi
		mov	esi,[eax+Element.firstChild]
		xor	eax,eax
		jmp	.first
.loop:		inc	eax
		mov	esi,[esi+Element.nextSibling]
.first:		or	esi,esi
		jnz	.loop
		pop	esi
		ret
;[cf]
;[cf]
;[of]:	createOneClass
;[c]Create one class
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		0 = collection
;[c]		1 = element
;[c]	ebx
;[c]		context
;[c]	esi
;[c]		current element
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]	edi
;[c]		the class
;[c]
createOneClass:	
		; Create the new element class
		push	ebx
		push	esi
		mov	ecx,ebx
		mov	ebx,eax
		mov	eax,esi
		call	newElementClass
		mov	edi,ebx		
		pop	esi
		pop	ebx

		jz	initializeClass
		ret
;[cf]
;[of]:	initializeClass
;[c]Initialize one class
;[c]
;[c]ARGUMENTS
;[c]	ebx
;[c]		context
;[c]	esi
;[c]		current source element
;[c]	edi
;[c]		class
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]
		struct	TreeBuilder
.context	rd	1	; the create class context
.attributeRoot	rd	1	; the root node for attributes
.elementRoot	rd	1	; the root node for elements
.rootElement	rd	1	; the root element
.offset		rd	1	; the attribute offset
.propertyCount	rd	1	; number of attributes/text element
.childCount	rd	1	; number of child classes
.childIndex	rd	1	; index to store next child class
.children	rd	1	; the array to store child classes

; Arguments and local variables for addItem
.collectionClass	rd	1	; 
.rootNode		rd	1	; the root node
.ignored		rd	1	; 1 if the element is an ignored element
.nameBegin		rd	1	;
.nameLimit		rd	1	;
.ignore			rd	1	;
		ends

initializeClass:
		; Already resolved ?
		cmp	[edi+ElementClass.status],RESOLVED
		jz	.resolved
		
		; Already being resolved ?
		cmp	[edi+ElementClass.status],RESOLVING
		jz	.circular
		
		; Mark as resolution in progress
		mov	[edi+ElementClass.status],RESOLVING
		
		push	ebx
		push	esi
		push	edi
		push	ebp
		sub	esp,TreeBuilder.sizeof
		mov	ebp,esp
		mov	[ebp+TreeBuilder.context],ebx
		mov	[ebp+TreeBuilder.rootElement],esi
		xor	eax,eax
		mov	[ebp+TreeBuilder.attributeRoot],eax
		mov	[ebp+TreeBuilder.elementRoot],eax
		mov	[ebp+TreeBuilder.propertyCount],eax
		mov	[ebp+TreeBuilder.childIndex],eax
		mov	[ebp+TreeBuilder.offset],Element.sizeof
		mov	eax,esi
		call	countChildren
		jnz	.error
		mov	[ebp+TreeBuilder.childCount],ebx
		
		;
		; Allocate memory for child collections
		;
		mov	eax,ebx
		shl	eax,2
		mov	ecx,4
		mov	edx,[ebp+TreeBuilder.context]
		push	edi
		call	allocateMemory
		mov	ebx,edi
		pop	edi
		jnz	.error
		mov	[edi+ElementClass.children],ebx
		mov	[ebp+TreeBuilder.children],ebx

		;
		; Text type : the first attribute is reserved
		; to store the text value.
		;
		cmp	[edi+ElementClass.type],TYPE_TEXT
		jnz	.notText
		add	[ebp+TreeBuilder.offset],Attribute.sizeof
		add	[ebp+TreeBuilder.propertyCount],1
.notText:

		; Build the attribute tree
		;
		mov	esi,[ebp+TreeBuilder.rootElement]
		call	buildTrees
		jnz	.error
		
		; Build the attribute map from the tree
		;
		mov	ebx,-1
		mov	esi,[ebp+TreeBuilder.attributeRoot]
		call	createAttributeMap
		jnz	.error
		mov	[edi+ElementClass.attributes],ebx

		; Build the element map from the tree
		;
		xor	ebx,ebx
		mov	esi,[ebp+TreeBuilder.elementRoot]
		call	createElementMap
		jnz	.error
		mov	[edi+ElementClass.elements],ebx
		
		;
		; Finalize:
		; - copy the number of properties
		; - setup the size of the element
		; - mark as resolved
		;
		mov	eax,[ebp+TreeBuilder.propertyCount]
		imul	ebx,eax,Attribute.sizeof
		add	ebx,Element.sizeof
		mov	ecx,[ebp+TreeBuilder.childCount]
		mov	[edi+ElementClass.propertyCount],eax
		mov	[edi+ElementClass.size],ebx
		mov	[edi+ElementClass.childCount],ecx
		mov	[edi+ElementClass.status],RESOLVED

		xor	eax,eax
		
.error:		lea	esp,[ebp+TreeBuilder.sizeof]	; zf unchanged
		pop	ebp
		pop	edi
		pop	esi
		pop	ebx
.resolved:	ret
;[c]
.circular:	mov	eax,RC_RECURSIVE_ELEMENT
		or	eax,eax
		ret
;[c]
;[c]SUB-FUNCTIONS
;[of]:	copyString
copyString:	push	esi
		push	edi
		rep movsb
		xor	eax,eax
		stosb
		pop	edi
		pop	esi
		ret
;[cf]
;[of]:	buildTrees
;[c]Build the tree of elements and the tree of attributes
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		the source element
;[c]	ebp
;[c]		the tree builder
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]
;[c]REMARKS
;[c]	The 'root' local variable will contain the root attribute map
;[c]
buildTrees:	push	ebx
		push	esi
		push	edi

		; Process all attributes of the element
		mov	esi,[esi+Element.firstChild]
		jmp	.first

.loop:		cmp	[esi+Element.id],attributeId
		jz	.attribute
		cmp	[esi+Element.id],textId
		jz	.txt
		cmp	[esi+Element.id],collectionId
		jz	.collection
		cmp	[esi+Element.id],elementId
		jz	.element
		cmp	[esi+Element.id],referenceId
		jz	.reference
		cmp	[esi+Element.id],includeId
		jz	.include
.next:		mov	esi,[esi+Element.nextSibling]
.first:		or	esi,esi
		jnz	.loop
		
		xor	eax,eax
.error:		pop	edi
		pop	esi
		pop	ebx
		ret
;[c]
;[c]Process a <attribute> element
;[c]
.attribute:	xor	eax,eax
		lea	edi,[ebp+TreeBuilder.attributeRoot]
		call	addItem
		jnz	.error
		jmp	.next
;[c]
;[c]Process a <text> element
;[c]
.txt:		xor	eax,eax
		jmp	.common
;[c]
;[c]Process a <collection> element
;[c]
.collection:
		; Create subclass
		sub	eax,eax
		mov	ebx,[ebp+TreeBuilder.context]
		call	createOneClass
		jnz	.error
		
		; Save it to the list
		mov	eax,[ebp+TreeBuilder.childIndex]
		mov	ecx,[ebp+TreeBuilder.children]
		mov	[ecx+eax*4],edi
		inc	eax
		mov	[ebp+TreeBuilder.childIndex],eax
		
		; Add it to the tree
		mov	eax,edi
		jmp	.common
;[c]
;[c]Process a <element> element
;[c]
.element:
		; Create subclass
		mov	eax,1
		mov	ebx,[ebp+TreeBuilder.context]
		call	createOneClass
		jnz	.error
		
		; Add it to the tree
		mov	eax,edi
		jmp	.common
;[c]
;[c]Process a <reference> element
;[c]
.reference:	lea	eax,[esi+Element.sizeof]	; eax to name attribute
		call	findClass
		mov	edi,ebx
		jnz	.error

		; Save it to the list
		mov	eax,[ebp+TreeBuilder.childIndex]
		mov	ecx,[ebp+TreeBuilder.children]
		mov	[ecx+eax*4],edi
		inc	eax
		mov	[ebp+TreeBuilder.childIndex],eax
		
		mov	eax,edi
;[c]
.common:	lea	edi,[ebp+TreeBuilder.elementRoot]
		call	addItem
		jnz	.error
		jmp	.next
;[c]
.include:	lea	eax,[esi+Element.sizeof]	; eax to name attribute
		call	findGroup
		jnz	.error
		
		push	esi
		mov	esi,ebx
		call	buildTrees
		pop	esi
		jmp	.next
;[c]
;[c]SUB-FUNCTIONS
;[of]:	addItem
;[c]Add one item to the tree
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		the collection class or null
;[c]	esi
;[c]		the element
;[c]	edi
;[c]		the root node of the tree (element or attribute)
;[c]	ebp
;[c]		local variables
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]
;[c]REMARKS
;[c]	It can be a text, attribute or collection item.
;[c]
addItem:	push	eax
		push	ebx
		lea	eax,[esi+Element.sizeof+ATTR_IGNORE*Attribute.sizeof]
		xor	ebx,ebx
		cmp	[eax+Attribute.begin],0
		jz	.found
		lea	ecx,[no]
		call	compareAttributeValue
		jz	.found
		mov	ebx,1
		lea	ecx,[yes]
		call	compareAttributeValue
		jz	.found
		
		pop	ebx
		pop	eax
		mov	eax,RC_INVALID_IGNORE
		or	eax,eax
		ret
		
.found:		mov	[ebp+TreeBuilder.ignore],ebx
		pop	ebx
		pop	eax

		mov	ecx,[esi+Element.sizeof+Attribute.limit]
		mov	edx,[esi+Element.sizeof+Attribute.begin]


;[c]
;[c]Add one item to the tree
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		the collection class or null
;[c]	ecx+edx
;[c]		the name of the element
;[c]	edi
;[c]		the root node of the tree (element or attribute)
;[c]	ebp
;[c]		local variables
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]
;[c]REMARKS
;[c]	It can be a text, attribute or collection item.
;[c]
;[c]
addItem2:	push	ebx
		push	esi
		push	edi
		push	ebp
		mov	[ebp+TreeBuilder.collectionClass],eax
		mov	[ebp+TreeBuilder.rootNode],edi
		mov	[ebp+TreeBuilder.nameLimit],ecx
		mov	[ebp+TreeBuilder.nameBegin],edx
		
		; empty name ?
		cmp	ecx,edx
		jz	.emptyName

		; esi = list
		; ebx = previous node
		mov	esi,[ebp+TreeBuilder.rootNode]
		mov	esi,[esi]
		xor	ebx,ebx

		; read char
.next:		mov	al,[edx]
		inc	edx
		
		push	ecx
		push	edx
		call	findOrCreateNode
		pop	edx
		pop	ecx
		jnz	.error
		; esi: list
		; edi: node

		; Attach to previous node
		or	ebx,ebx
		jz	.root
		cmp	[ebx+Node.succ],0
		jnz	.root
		mov	[ebx+Node.succ],esi
.root:
		; Save the root list
		mov	eax,[ebp+TreeBuilder.rootNode]
		cmp	dword [eax],0
		jnz	.hasRoot
		mov	[eax],esi
.hasRoot:

		mov	ebx,edi			; the previous node is the current one
		mov	esi,[ebx+Node.succ]	; get the successor
		cmp	ecx,edx
		jnz	.next
		
		; Save the attribute offset
		; and update it
		
		; Is there already something with same name ?
		cmp	dword [ebx+Node.index],-1
		jz	.noconflict
		cmp	dword [ebx+Node.index],Element.reserved	; no conflict if ignored
		jnz	.conflict
.noconflict:	cmp	dword [ebx+Node.collectionClass],0
		jnz	.conflict

		mov	ecx,[ebp+TreeBuilder.collectionClass]
		or	ecx,ecx
		jz	.txt

		mov	[ebx+Node.collectionClass],ecx

		; If the it is not a collection but an element
		; it must also be assigned an offset like a text element
		cmp	dword [ecx+ElementClass.offset],0
		jz	.common

		cmp	[ebp+TreeBuilder.ignore],1
		jz	.ignore

		; If the element is shared, it must be solved first,
		; then duplicated.
		;
		cmp	byte [ecx+ElementClass.shared],0
		jz	.notShared

		push	ebx
		push	ecx
		mov	ebx,[ebp+TreeBuilder.context]
		mov	esi,[ecx+ElementClass.source]
		mov	edi,ecx
		call	initializeClass
		pop	ecx
		pop	ebx
		jnz	.error
		
		push	ebx
		mov	ebx,[ebp+TreeBuilder.context]
		mov	eax,ecx
		call	copyElementClass
		mov	ecx,ebx
		pop	ebx
		jnz	.error

		; Replace the class by the duplicata
		mov	[ebx+Node.collectionClass],ecx
		jmp	.notShared
		
.txt:		cmp	[ebp+TreeBuilder.ignore],1
		jz	.ignore

.notShared:	mov	eax,[ebp+TreeBuilder.offset]
		mov	[ebx+Node.index],eax
		add	eax,Attribute.sizeof
		mov	[ebp+TreeBuilder.offset],eax
		add	[ebp+TreeBuilder.propertyCount],1
		jmp	.common

.ignore:	mov	[ebx+Node.index],Element.reserved

.common:	mov	ecx,[ebp+TreeBuilder.nameBegin]
		mov	edx,[ebp+TreeBuilder.nameLimit]
		call	newDString
		mov	[ebx+Node.nameBegin],ecx
		mov	[ebx+Node.nameLimit],edx
		
		xor	eax,eax
.error:		or	eax,eax
		pop	ebp
		pop	edi
		pop	esi
		pop	ebx
		ret

.emptyName:	mov	eax,RC_EMPTY_NAME
		jmp	.error

.conflict:	mov	eax,RC_ATTR_DEFINED
		jmp	.error
;[c]
;[of]:newDString
;[c]Create a new DString by copying another one
;[c]
;[c]ARGUMENTS
;[c]	ecx
;[c]		begin
;[c]	edx
;[c]		end
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]	ecx
;[c]		begin (copy)
;[c]	edx
;[c]		end (copy)
;[c]
newDString:	push	esi
		push	edi
		
		mov	esi,ecx
		mov	eax,edx
		sub	eax,esi
		mov	ecx,1
		mov	edx,[ebp+TreeBuilder.context]
		push	eax
		call	allocateMemory
		pop	ecx
		jnz	.error
		push	ecx
		push	edi
		rep 
		movsb
		pop	ecx
		pop	edx
		add	edx,ecx
		
		xor	eax,eax
.error:		pop	edi
		pop	esi
		ret
;[cf]
;[cf]
;[cf]
;[of]:	createElementMap
;[c]Create an element map for one node
;[c]
;[c]ARGUMENTS
;[c]	ebx
;[c]		the previous node or nil
;[c]	esi
;[c]		the node
;[c]	ebp
;[c]	
;[c]RETURN VALUE
;[c]	eax+zf
;[c]		error code
;[c]	ebx
;[c]		the map
;[c]
createElementMap:
		push	esi
		push	edi

		; Empty node ?
		or	esi,esi
		jz	.empty

		call	createMap
		
		; If the previous node contains an offset, create the
		; attribute and make any non-name char a
		; target to this attribute.
		;
		; Note: it cannot happen on the root node since
		; a name cannot be empty.
		or	ebx,ebx
		jz	.noAttr
		cmp	[ebx+Node.collectionClass],0
		jnz	.elem
		cmp	[ebx+Node.index],-1
		jz	.noAttr
.elem:
		; Case where a name is a prefix of another name:
		;   ab
		;   abc
		; ab must be added on non-chars of the abc's map
		;
		;mov	eax,8
		;mov	ecx,4
		;push	edi
		;mov	edx,[ebp+TreeBuilder.context]
		;call	allocateMemory
		;pop	edx
		;jnz	.error
		;mov	ecx,[ebx+Node.collectionClass]
		;mov	word [edi],0
		;mov	[edi+4],ecx
		
		push	ebx
		push	esi
		mov	esi,ebx
		call	createTerminalElement
		mov	ecx,ebx
		pop	esi
		pop	ebx
		jnz	.error
		
		push	edi
		push	edx
		mov	edx,edi
		lea	edi,[ecx+3] ; set bit 0 & 1 to 1
		call	mapTerminal
		pop	edx
		pop	edi
.noAttr:

		; Process each node
.lp:		cmp	[esi+Node.shared],0
		jnz	.shared
		
		; The node has only one possible attribute:
		; Create the attribute
		
		call	createElement
		jnz	.error		
		add	ebx,1	; set bit 0 to 1
		jmp	.next
		
		; The node has multiple possible attributes:
		; Create a submap and point to it
.shared:	push	esi
		mov	ebx,esi
		mov	esi,[esi+Node.succ]
		call	createElementMap
		pop	esi
		jnz	.error

 		; Point to the attribute or map (depending on bit 0)
.next:		movzx	eax,[esi+Node.char]
		mov	[edi+eax*4],ebx
		
		mov	esi,[esi+Node.next]
		or	esi,esi
		jnz	.lp
		
		mov	ebx,edi
.ok:		xor	eax,eax
.error:		pop	edi
		pop	esi
		ret

.empty:		mov	ebx,noElement
		jmp	.ok
;[c]
;[of]:createElement
;[c]Create an element
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		Node
;[c]
;[c]RETURN VALUES
;[c]	zf+eax
;[c]		Error code
;[c]	ebx
;[c]		Element
;[c]
createElement:

		; Compute the number of remaining chars
		xor	eax,eax
		mov	ebx,esi
		sub	eax,1			; avoid jmp+1
.nextChar:	add	eax,1
		mov	ebx,[ebx+Node.succ]
		or	ebx,ebx
		jnz	.nextChar
		
		; Add null char
		; Add flag char
		; Add pointer
		; Align to multiple of 4
		add	eax,1+1+3+4
		and	eax,not 3
		
		cmp	[esi+Node.collectionClass],0
		jnz	.coll
		add	eax,TextElementClass.sizeof - 4

		; Allocate memory for element
.coll:		mov	ecx,4
		push	edi
		mov	edx,[ebp+TreeBuilder.context]
		call	allocateMemory
		mov	ebx,edi
		pop	edi
		jnz	.error
		
		; Copy remaining chars into attribute
		mov	ecx,ebx
		mov	eax,[esi+Node.succ]
		mov	edx,esi
		or	eax,eax
		jz	.skip2
.nextChar2:	mov	edx,eax
		mov	al,[edx+Node.char]
		mov	[ecx],al
		add	ecx,1
		mov	eax,[edx+Node.succ]
		or	eax,eax
		jnz	.nextChar2
.skip2:		mov	byte [ecx],0
		add	ecx,1

		mov	eax,[edx+Node.collectionClass]
		or	eax,eax
		setz	byte [ecx]
		add	ecx,1+3
		and	ecx,not 3
		or	eax,eax
		jz	.txt
		
		; Write Collection Class Information
		mov	[ecx],eax
		
		cmp	[eax+ElementClass.offset],0
		jz	.ok
		mov	ecx,[edx+Node.index]
		mov	[eax+ElementClass.offset],ecx
		jmp	.ok

		; Write Text Class Information
.txt:		push	esi
		push	edi
		mov	eax,[edx+Node.index]
		mov	esi,[edx+Node.nameBegin]
		mov	edi,[edx+Node.nameLimit]
		mov	[ecx+TextElementClass.offset],eax
		mov	[ecx+TextElementClass.begin],esi
		mov	[ecx+TextElementClass.limit],edi
		pop	edi
		pop	esi

.ok:		xor	eax,eax
.error:		ret
;[cf]
;[of]:createTerminalElement
;[c]Create a terminal element
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		Node
;[c]
;[c]RETURN VALUES
;[c]	zf+eax
;[c]		Error code
;[c]	ebx
;[c]		Element
;[c]
createTerminalElement:

		; Add null char
		; Add flag char
		; Add pointer
		; Align to multiple of 4
		mov	eax,8
		cmp	[esi+Node.collectionClass],0
		jnz	.coll
		add	eax,TextElementClass.sizeof - 4

		; Allocate memory for element
.coll:		mov	ecx,4
		push	edi
		mov	edx,[ebp+TreeBuilder.context]
		call	allocateMemory
		mov	ebx,edi
		pop	edi
		jnz	.error
		
		; Copy remaining chars into attribute
		mov	ecx,ebx
		mov	byte [ecx],0
		add	ecx,1
		mov	eax,[esi+Node.collectionClass]
		or	eax,eax
		setz	byte [ecx]
		add	ecx,1+3
		and	ecx,not 3
		or	eax,eax
		jz	.txt
		
		; Write Collection Class Information
		mov	[ecx],eax

		cmp	[eax+ElementClass.offset],0
		jz	.ok
		mov	ecx,[esi+Node.index]
		mov	[eax+ElementClass.offset],ecx
		jmp	.ok

		; Write Text Class Information
.txt:		push	edi
		mov	eax,[esi+Node.index]
		mov	edx,[esi+Node.nameBegin]
		mov	edi,[esi+Node.nameLimit]
		mov	[ecx+TextElementClass.offset],eax
		mov	[ecx+TextElementClass.begin],edx
		mov	[ecx+TextElementClass.limit],edi
		pop	edi

.ok:		xor	eax,eax
.error:		ret
;[cf]
;[cf]
;[of]:	createAttributeMap
;[c]Create an attribute map for one node
;[c]
;[c]ARGUMENTS
;[c]	ebx
;[c]		-1 if the node does not have an attribute
;[c]	esi
;[c]		the node
;[c]	ebp
;[c]	
;[c]RETURN VALUE
;[c]	eax+zf
;[c]		error code
;[c]	ebx
;[c]		the map
;[c]
createAttributeMap:
		; The node is null: return an empty map
		or	esi,esi
		jnz	.noEmpty
		mov	ebx,noAttribute
		xor	eax,eax
		ret
.noEmpty:
		
		push	esi
		push	edi

		call	createMap
		
		; If the previous node contains an offset, create the
		; attribute and make any non-name char a
		; target to this attribute.
		;
		; Note: it cannot happen on the root node since
		; a name cannot be empty.
		cmp	ebx,-1
		jz	.noAttr
		
		push	edi
		xor	eax,eax
		call	allocateAttribute
		pop	edx
		jnz	.error
		mov	byte [edi],0
		mov	[edi+1],ebx
		mov	ebx,edx
		add	edi,3	; set bit 0 & 1 to 1
		call	mapTerminal
		mov	edi,ebx
.noAttr:

		; Process each node
.lp:		cmp	[esi+Node.shared],0
		jnz	.shared
		
		; The node has only one possible attribute:
		; Create the attribute
		
		call	createAttribute
		jnz	.error		
		add	ebx,1	; set bit 0 to 1
		jmp	.next
		
		; The node has multiple possible attributes:
		; Create a submap and point to it
.shared:	push	esi
		mov	ebx,[esi+Node.index]
		mov	esi,[esi+Node.succ]
		call	createAttributeMap
		pop	esi
		jnz	.error

 		; Point to the attribute or map (depending on bit 0)
.next:		movzx	eax,[esi+Node.char]
		mov	[edi+eax*4],ebx
		
		mov	esi,[esi+Node.next]
		or	esi,esi
		jnz	.lp
		
		xor	eax,eax
		mov	ebx,edi
.error:		pop	edi
		pop	esi
		ret
;[c]
;[of]:mapTerminal
;[c]Set the object for each invalid name char
;[c]
;[c]ARGUMENT
;[c]	edx
;[c]		the map
;[c]	edi
;[c]		the object
;[c]
mapTerminal:	push	esi

		mov	ecx,256
		lea	esi,[terminalChar]
.next:		cmp	byte [esi],1
		jz	.skip
		mov	[edx],edi
.skip:		add	edx,4
		add	esi,1
		sub	ecx,1
		jnz	.next
		
		pop	esi
		ret
;[cf]
;[of]:createMap
createMap:
		; Allocate a map
		call	allocateMap
		jnz	.error

		; Initialize map
		push	edi
		mov	ecx,256
		mov	eax,1
		rep
		stosd
		pop	edi
		
		xor	eax,eax
.error:		ret
;[cf]
;[of]:allocateMap
;[c]Allocates a map
;[c]
;[c]ARGUMENTS
;[c]	ebp
;[c]		the tree builder local variables
;[c]		
;[c]RETURN VALUES
;[c]	zf
;[c]		0 if not  enough memory
;[c]	eax
;[c]		error code
;[c]	edi
;[c]		the map
;[c]
MAP_SIZE	=	256*4
MAP_ALIGN	=	64
;[c]
allocateMap:	mov	ecx,MAP_ALIGN
		mov	eax,MAP_SIZE
		mov	edx,[ebp+TreeBuilder.context]
		jmp	allocateMemory
;[cf]
;[of]:createAttribute
;[c]Create an attribute
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		Node
;[c]
;[c]RETURN VALUES
;[c]	zf+eax
;[c]		Error code
;[c]	ebx
;[c]		Attribute
;[c]
createAttribute:

		; Compute the number of remaining chars
		xor	eax,eax
		mov	ebx,esi
		sub	eax,1			; avoid jmp+1
.nextChar:	add	eax,1
		mov	ebx,[ebx+Node.succ]
		or	ebx,ebx
		jnz	.nextChar
		
		; Allocate memory for attribute
		push	edi
		call	allocateAttribute
		mov	ebx,edi
		pop	edi
		jnz	.error

		; Copy remaining chars into attribute
		mov	ecx,ebx
		mov	edx,esi
		mov	eax,[edx+Node.succ]
		or	eax,eax
		jz	.skip2
.nextChar2:	mov	edx,eax
		mov	al,[edx+Node.char]
		mov	[ecx],al
		add	ecx,1
		mov	eax,[edx+Node.succ]
		or	eax,eax
		jnz	.nextChar2
.skip2:		mov	byte [ecx],0

		; Append the index from the last node (edx)
		mov	eax,[edx+Node.index]
		mov	[ecx+1],eax
		
		xor	eax,eax
.error:		ret
;[cf]
;[of]:allocateAttribute
;[c]Allocates an attribute
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		extra size
;[c]	ebp
;[c]		the tree builder local variables
;[c]		
;[c]RETURN VALUES
;[c]	zf
;[c]		0 if not  enough memory
;[c]	eax
;[c]		error code
;[c]	edi
;[c]		the map
;[c]
allocateAttribute:
		mov	ecx,4
		add	eax,1+4
		mov	edx,[ebp+TreeBuilder.context]
		jmp	allocateMemory
;[cf]
;[cf]
;[of]:	countChildren
;[c]Count number of child classes of type collection
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		the element
;[c]
;[c]RETURN VALUES
;[c]	ebx
;[c]		the number of child classes
;[c]
countChildren:	push	esi
		push	edi
		mov	esi,[eax+Element.firstChild]
		xor	edi,edi
		jmp	.first
.loop:		cmp	[esi+Element.id],collectionId
		jz	.count
		cmp	[esi+Element.id],documentId
		jz	.count
		cmp	[esi+Element.id],referenceId
		jz	.count
		cmp	[esi+Element.id],includeId
		jnz	.next

		lea	eax,[esi+Element.sizeof]	; eax to name attribute
		call	findGroup
		jnz	.error
		
		mov	eax,ebx
		call	countChildren
		add	edi,ebx
		jmp	.next

.count:		inc	edi
.next:		mov	esi,[esi+Element.nextSibling]
.first:		or	esi,esi
		jnz	.loop
		mov	ebx,edi
		xor	eax,eax
.error:		pop	edi
		pop	esi
		ret
;[cf]
;[of]:	findClass
;[c]find a class by name
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		the name attribute to look for
;[c]	ebp
;[c]		the context
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]	ebx
;[c]		the class
;[c]
findClass:	push	esi
		push	edi
		mov	edi,eax
		mov	esi,[ebp+TreeBuilder.context]
		mov	esi,[esi+CreateClassContext.classes]
		jmp	.next

.loop:		push	eax
		lea	eax,[eax+ElementClass.name]
		lea	ebx,[edi+Attribute.begin]
		call	compareAttributes
		pop	ebx
		jnz	.next
		
		; found
		xor	eax,eax
		jmp	.done

.next:		lodsd
		or	eax,eax
		jnz	.loop

		; not found		
		mov	eax,RC_UNDEFINED_CLASS
		or	eax,eax

.done:		pop	edi
		pop	esi
		ret
;[c]
;[c]
;[cf]
;[of]:	findGroup
;[c]Find a group by name
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		the name attribute
;[c]
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		nz if not found
;[c]	ebx
;[c]		the group element
;[c]
findGroup:	push	esi
		push	edi

		mov	esi,[ebp+TreeBuilder.context]
		mov	esi,[esi+CreateClassContext.rootElement]
		mov	esi,[esi+Element.firstChild]
		mov	ebx,eax
		jmp	.first
		
.loop:		cmp	[esi+Element.id],groupId
		jnz	.next

		lea	eax,[esi+Element.sizeof+ATTR_NAME*Attribute.sizeof]
		call	compareAttributes
		jnz	.next
		xor	eax,eax
		mov	ebx,esi
		jmp	.found

.next:		mov	esi,[esi+Element.nextSibling]
.first:		or	esi,esi
		jnz	.loop

		mov	eax,RC_UNDEFINED_GROUP
		or	eax,eax
.found:		pop	edi
		pop	esi
		ret
;[cf]
;[c]
;[c]CLASSES
;[of]:	Node
;[of]:Comment
;[c]Node
;[c]
;[c]A Node object is just a part of a tree that is a temporary object used to
;[c]build the maps of attributes/elements.
;[c]
;[c]The goal is to have an efficient implementation of a dictionary,
;[c]i.e. a set of name -> value.
;[c]
;[c]A null node pointer is an empty node. So a list is simply initialized
;[c]by clearing a register.
;[c]
;[c]A node is also a list of nodes, one for each char that can appear at this 
;[c]level. The list of nodes is obtained by following the 'next' property.
;[c]
;[c]When a character matches, the 'succ' gives the next node for the next
;[c]possible character(s).
;[c]
;       succ
; Node ---------> Node
;  |               |next
;  |next
;  |
;  |    succ
; Node ---------> Node
;  |
;  |next
;  |
;  |    succ
; Node ---------> Node
;  |
;  |next
;  .
;  .

;[cf]
;[of]:Definitions
		struct		Node
.next		rd	1
.succ		rd	1
.char		rb	1
.shared		rb	1
		rb	2
.index		rd	1
.collectionClass	rd	1
.nameBegin	rd	1
.nameLimit	rd	1
		ends
;[cf]
;[c]
;[of]:findOrCreateNode
;[c]Find or create a node
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		the parent node or nil
;[c]	al
;[c]		the char
;[c]
;[c]RETURN VALUES
;[c]	zf
;[c]		0 if error
;[c]	eax
;[c]		error code
;[c]	esi
;[c]		the new parent node
;[c]	edi
;[c]		the found or created node
;[c]
;[c]REMARKS
;[c]	If the node already exists, the shared flag is set.
;[c]	
findOrCreateNode:

		call	findNode
		jz	.notFound
		
		mov	[edi+Node.shared],1
		jmp	.ok

		; Allocate a node
.notFound:	push	eax
		call	allocateNode
		pop	edx
		jnz	.error

		; Append node
		call	appendNode
		
		; Initialize node
		xor	eax,eax
		mov	[edi+Node.next],eax
		mov	[edi+Node.succ],eax
		mov	[edi+Node.char],dl
		mov	[edi+Node.shared],al
		mov	[edi+Node.index],-1
		mov	[edi+Node.collectionClass],eax
		
.ok:		xor	eax,eax
.error:		ret
;[cf]
;[of]:allocateNode
;[c]Allocates a node
;[c]
;[c]ARGUMENTS
;[c]	ebp
;[c]		the tree builder local variables
;[c]		
;[c]RETURN VALUES
;[c]	zf
;[c]		0 if not  enough memory
;[c]	eax
;[c]		error code
;[c]	edi
;[c]		the node
;[c]
allocateNode:	mov	ecx,4
		mov	eax,Node.sizeof
		mov	edx,[ebp+TreeBuilder.context]
		jmp	allocateMemory
;[cf]
;[of]:appendNode
;[c]Append a node
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		parent node
;[c]	edi
;[c]		node to append to parent
;[c]
;[c]RETURN VALUES
;[c]	esi
;[c]		parent node
;[c]	edi
;[c]		node to append
;[c]
;[c]REMARKS
;[c]	if the parent node is nil (i.e. empty), edi becomes the parent.
;[c]
appendNode:	call	lastNode
		jz	.empty
		mov	[esi+Node.next],edi
		ret
.empty:		mov	esi,edi
		ret
;[cf]
;[of]:findNode
;[c]Find a node
;[c]
;[c]ARGUMENTS
;[c]	al
;[c]		char
;[c]	esi
;[c]		parent node
;[c]
;[c]RETURN VALUES
;[c]	edi
;[c]		search node or nil
;[c]	zf
;[c]		1 if not found
;[c]	
findNode:	mov	edi,esi
		jmp	.first

.next:		cmp	al,[edi+Node.char]
		jz	.done
		mov	edi,[edi+Node.next]
.first:		or	edi,edi
		jnz	.next
	
.done:		or	edi,edi
		ret
;[cf]
;[of]:lastNode
;[c]Returns the last node
;[c]
;[c]ARGUMENTS
;[c]	esi
;[c]		parent node
;[c]
;[c]RETURN VALUES
;[c]	esi
;[c]		the last node
;[c]	zf
;[c]		1 if the list of nodes is empty
;[c]	
lastNode:	or	esi,esi
		jnz	.first
		ret
.next:		mov	esi,eax
.first:		mov	eax,[esi+Node.next]
		or	eax,eax
		jnz	.next
		or	esi,esi
		ret
;[cf]
;[cf]
;[cf]

;[of]:	newElementClass
;[c]Create a new element class
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		source element
;[c]	ebx
;[c]		is element
;[c]	ecx
;[c]		context
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]	ebx
;[c]		the new element class
;[c]	
newElementClass:
		push	esi
		push	edi
		mov	esi,eax

		;
		; Allocate memory for element class + name
		;
		mov	eax,[esi+Element.sizeof+Attribute.limit]
		sub	eax,[esi+Element.sizeof+Attribute.begin]
		add	eax,ElementClass.sizeof+1
		mov	edx,ecx
		mov	ecx,4
		call	allocateMemory
		jnz	.error

		;
		; Reset offset
		;
		; the offset is set to 0 if the element is a collection,
		; and it is temporary set to 1 if it is an element, it
		; is just a flag now, but it will replaced by an offset
		; later.
		;
		mov	[edi+ElementClass.offset],ebx
		mov	[edi+ElementClass.shared],0
		mov	[edi+ElementClass.status],UNRESOLVED

		;
		; Setup type
		;
		lea	eax,[esi+Element.sizeof+ATTR_TYPE*Attribute.sizeof]
		mov	ebx,TYPE_MIXED
		lea	ecx,[mixedValue]
		call	compareAttributeValue
		jz	.found
		mov	ebx,TYPE_CONTAINER
		lea	ecx,[textValue]
		call	compareAttributeValue
		jnz	.found
		mov	ebx,TYPE_TEXT
.found:		mov	[edi+ElementClass.type],ebx

		;
		; Copy and Set Name
		;
		push	esi
		lea	eax,[edi+ElementClass.sizeof]
		mov	[edi+ElementClass.name],eax
		push	edi
		mov	ecx,[esi+Element.sizeof+Attribute.limit]
		mov	esi,[esi+Element.sizeof+Attribute.begin]
		sub	ecx,esi
		mov	edi,eax
		rep movsb
		mov	esi,edi
		xor	eax,eax
		stosb
		pop	edi
		mov	[edi+ElementClass.nameLimit],esi
		pop	esi

		;
		; Setup id
		;
		mov	eax,[esi+Element.sizeof+ATTR_ID*Attribute.sizeof+Attribute.begin]
		mov	ebx,[esi+Element.sizeof+ATTR_ID*Attribute.sizeof+Attribute.limit]
		call	toInteger
		jnz	.error
		mov	[edi+ElementClass.id],ebx

		xor	eax,eax
		mov	ebx,edi
.error:		pop	edi
		pop	esi
		ret
;[cf]
;[of]:	copyElementClass
;[c]Copy an element class
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		source class
;[c]	ebx
;[c]		context
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]	ebx
;[c]		the new element class
;[c]	
copyElementClass:
		push	esi
		push	edi
		mov	esi,eax

		;
		; Allocate memory for element class
		;
		mov	eax,ElementClass.sizeof
		mov	edx,ebx
		mov	ecx,4
		call	allocateMemory
		jnz	.error

		mov	ebx,edi
		mov	ecx,ElementClass.sizeof / 4
		rep	movsd

		xor	eax,eax
.error:		pop	edi
		pop	esi
		ret
;[cf]
;[cf]
;[cf]

;[of]:Utility Functions
;[of]:compareAttributeValue
;[c]Compare the value of an attribute
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		the attribute
;[c]	ecx
;[c]		the value (zero terminated)
;[c]
;[c]RETURN VALUES
;[c]	zf
;[c]		1 if equal
;[c]
compareAttributeValue:
		push	esi
		push	edi

		mov	edi,ecx
		mov	esi,[eax+Attribute.begin]
		mov	ecx,[eax+Attribute.limit]
		sub	ecx,esi
		jz	.done
.next:		cmpsb
		jnz	.diff
		sub	ecx,1
		jnz	.next

.done:		cmp	byte [edi],0

.diff:		pop	edi
		pop	esi
		ret
;[cf]
;[of]:compareAttributes
;[c]Compare two attributes
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		the first attribute
;[c]	ebx
;[c]		the second attribute
;[c]
;[c]RETURN VALUES
;[c]	zf
;[c]		1 if equal
;[c]
compareAttributes:
		push	esi
		push	edi
		mov	esi,[eax+Attribute.begin]
		mov	edi,[ebx+Attribute.begin]
		
		; Compare length
		mov	ecx,[eax+Attribute.limit]
		mov	edx,[ebx+Attribute.limit]
		sub	ecx,esi
		sub	edx,edi
		cmp	ecx,edx
		jnz	.diff

		repz	cmpsb
.diff:
		pop	edi
		pop	esi
		ret
;[cf]
;[of]:toInteger
;[c]Converts a string to an integer
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		the string to parse
;[c]	ebx
;[c]		the end of string
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]	ebx
;[c]		integer value
;[c]
toInteger:	push	esi
		push	edi
		mov	esi,eax
		mov	edi,ebx
		xor	eax,eax
		jmp	.first

.loop:		movzx	ecx,byte [esi]
		cmp	cl,'0'
		jc	.error
		cmp	cl,'9'+1
		jnc	.error
		inc	esi
		mov	edx,10
		imul	eax,edx
		sub	cl,'0'
		add	eax,ecx
.first:		cmp	esi,edi
		jnz	.loop

		mov	ebx,eax
		xor	eax,eax

.done:		pop	edi
		pop	esi
		ret
;[c]
.error:		mov	eax,RC_INVALID_ID
		or	eax,eax
		jmp	.done
;[cf]
;[cf]
;[of]:Memory
;[of]:allocateMemory
;[c]Allocates a memory block
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		size
;[c]	ecx
;[c]		alignment
;[c]	edx
;[c]		context
;[c]		
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]	edi
;[c]		the object
;[c]
allocateMemory:	mov	edi,[edx+MemoryContext.base]
		sub	ecx,1
		add	edi,ecx
		not	ecx
		and	edi,ecx
		add	eax,edi
		cmp	eax,[edx+MemoryContext.limit]
		jnc	.chunkFull
		mov	[edx+MemoryContext.base],eax
		xor	eax,eax
		ret
;[c]
.chunkFull:	push	edx
		push	ebp
		mov	ebp,edx
		sub	eax,edi
		call	extendMemory	; let's assume that alignment is ok
		pop	ebp
		pop	edx
		ret
;[cf]
;[of]:extendMemory
;[c]Extend memory
;[c]
;[c]When there is not enough memory available, a new chunk is created
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		size
;[c]	ebp
;[c]		the parse context
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]	edi
;[c]		the allocated memory buffer
;[c]
extendMemory:	push	eax
		mov	ecx,[ebp+MemoryContext.chunkSize]
		add	eax,ecx
		call	newChunk
		pop	ecx
		jnz	.error
		
		mov	edi,[ebp+MemoryContext.base]
		add	ecx,edi
		mov	[ebp+MemoryContext.base],ecx

		xor	eax,eax
.error:		ret
;[cf]
;[of]:releaseChunks
;[c]Release the memory handled by the memory context
;[c]
;[c]ARGUMENTS
;[c]	ebp
;[c]		the context
;[c]
releaseChunks:	push	ebx
		mov	eax,[ebp+MemoryContext.chunks]
		or	eax,eax
		jz	.done
.loop:		mov	ebx,[eax]
		call	freeChunk
		mov	eax,ebx
		or	eax,eax
		jnz	.loop
.done:		pop	ebx
		ret		
;[cf]
;[of]:newChunk
;[c]Create a new chunk of memory
;[c]
;[c]ARGUMENTS
;[c]	ebp
;[c]		the parse context
;[c]	eax
;[c]		the size of chunk
;[c]
;[c]RETURN VALUES
;[c]	eax+zf
;[c]		error code
;[c]
newChunk:	mov	ecx,eax
		add	eax,HEADER_SIZE		; size for link
		push	ecx
		push	eax
		call	[mallocFunction]
		add	esp,4
		pop	ecx
		or	eax,eax
		jz	.outOfMemory
		mov	edx,[ebp+MemoryContext.chunks]
		mov	[eax],edx
		mov	[ebp+MemoryContext.chunks],eax
		add	eax,HEADER_SIZE
		add	ecx,eax
		mov	[ebp+MemoryContext.base],eax
		mov	[ebp+MemoryContext.limit],ecx
		
		xor	eax,eax
		ret
;[c]
.outOfMemory:	mov	eax,RC_MEMORY
		or	eax,eax
		ret
;[cf]
;[of]:freeChunk
;[c]Free a chunk
;[c]
;[c]ARGUMENTS
;[c]	eax
;[c]		the chunk
;[c]
freeChunk:	push	eax
		call	[freeFunction]
		add	esp,4
		ret
;[cf]
;[cf]

;[of]:Data
	align	4

;[of]:S
;[c]The blank map
;[c]
;[c]	Flag for each character:
;[c]	- 1 for blank characters (9, 10, 13, 32)
;[c]	- 0 for other characters
;[c]
S:		db	0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
;[cf]
;[of]:RAC
;[c]Regular Attribute Chars
;[c]
;[c]	Flag for each character:
;[c]	- 1 for special chars (" ' & \0)
;[c]	- 0 for other characters
;[c]
RAC:		db	1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,1,0,0,0,1,1,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
;[cf]
;[of]:terminalChar
;[c]Any zero char is a terminator for an attribute name or an element name
;[c]
terminalChar:	db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0	; -.
		db	1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0 ; :
		db	0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		db	1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1 ; _
		db	0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		db	1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0
		db	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		db	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		db	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		db	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		db	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		db	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		db	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		db	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
;[cf]
;[of]:digit
;[c]Two flags for each chars:
;[c]	- bit 0 for decimal chars
;[c]	- bit 1 for hexadecimal chars
;[c]
digit:		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	3,3,3,3,3,3,3,3,3,3,0,0,0,0,0,0
		db	0,2,2,2,2,2,2,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,2,2,2,2,2,2,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
;[cf]
;[of]:xdigit
;[c]Hexadecimal value of a char, assuming that the char is a valid 
;[c]hexadecimal digit.
;[c]
xdigit:		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0
		db	0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
;[cf]
;[of]:noElement / noAttribute
;[c]The default map for element without child elements (attribute only elements).
;[c]
noAttribute:
noElement:
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
;[cf]
;[of]:PubidChar
;[c]Valid characters for PubidLiteral
;[c]
PubidChar:	db	0,0,0,0,0,0,0,0,0,0,1,0,0,1,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1
		db	1,1,1,1,1,1,1,1,1,1,1,1,0,1,0,1
		db	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		db	1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1
		db	0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		db	1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
		db	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
;[cf]
;[of]:invalidClass
;[c]This special class is used to ignore unknown elements when
;[c]parsing in non strict mode.
;[c]
invalidClass:
		dd	Element.reserved	; store as ignored
		dd	invalidName
		dd	invalidName+1
		dd	Element.sizeof + 0 * Attribute.sizeof
		dd	0			; null id
		dd	TYPE_CONTAINER
		dd	0			; no child
		dd	0			; no element
		dd	noAttribute
		dd	noElement
;[cf]

;[of]:Schema Class
;[c]Schema Class
;[c]
SchemaClass:	dd	0
		dd	schemaName
		dd	schemaName+6
		dd	Element.sizeof
		dd	schemaId
		dd	TYPE_CONTAINER
		dd	0
		dd	0
		dd	noAttribute
		dd	schemaMap

;[of]:Attribute Class
;[c]Attribute Class
;[c]
attributeClass:	dd	0
		dd	attributeName
		dd	attributeName+9
		dd	Element.sizeof + 2 * Attribute.sizeof
		dd	attributeId
		dd	TYPE_CONTAINER
		dd	2
		dd	0
		dd	nameIgnoreAttr
		dd	noElement

;[cf]
;[of]:Text Class
;[c]Text Class
;[c]
textClass:	dd	0
		dd	textName
		dd	textName+4
		dd	Element.sizeof + 2 * Attribute.sizeof
		dd	textId
		dd	TYPE_CONTAINER
		dd	2
		dd	0
		dd	nameIgnoreAttr
		dd	noElement

;[cf]
;[of]:Document Class
documentClass:	dd	0
		dd	documentName
		dd	documentName+8
		dd	Element.sizeof + 4 * Attribute.sizeof
		dd	documentId
		dd	TYPE_CONTAINER
		dd	4
		dd	0
		dd	nameAndTypeAttr
		dd	elementMap
;[cf]
;[of]:Collection Class
collectionClass:
		dd	0
		dd	collectionName
		dd	collectionName+10
		dd	Element.sizeof + 4 * Attribute.sizeof
		dd	collectionId
		dd	TYPE_CONTAINER
		dd	4
		dd	0
		dd	nameAndTypeAttr
		dd	elementMap
;[cf]
;[of]:Group Class
groupClass:
		dd	0
		dd	groupName
		dd	groupName+5
		dd	Element.sizeof + 4 * Attribute.sizeof
		dd	groupId
		dd	TYPE_CONTAINER
		dd	4
		dd	0
		dd	nameAndTypeAttr
		dd	elementMap
;[cf]
;[of]:Element Class
elementClass:
		dd	0
		dd	elementName
		dd	elementName+7
		dd	Element.sizeof + 4 * Attribute.sizeof
		dd	elementId
		dd	TYPE_CONTAINER
		dd	4
		dd	0
		dd	nameAndTypeAttr
		dd	elementMap
;[cf]
;[of]:Reference Class
referenceClass:
		dd	0
		dd	referenceName
		dd	referenceName+9
		dd	Element.sizeof + 2 * Attribute.sizeof
		dd	referenceId
		dd	TYPE_CONTAINER
		dd	2
		dd	0
		dd	nameIgnoreAttr
		dd	noElement
;[cf]
;[of]:Include Class
includeClass:
		dd	0
		dd	includeName
		dd	includeName+7
		dd	Element.sizeof + 1 * Attribute.sizeof
		dd	includeId
		dd	TYPE_CONTAINER
		dd	1
		dd	0
		dd	nameAttr
		dd	noElement
;[cf]

;[of]:Element maps
		align	4
schemaMap:	dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,.c+1,.d+1,.e+1,1,.g+1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1

.c:		align	4
		db	"ollection",0,0
		align	4
		dd	collectionClass

.d:		align	4
		db	"ocument",0,0
		align	4
		dd	documentClass

.e:		align	4
		db	"lement",0,0
		align	4
		dd	elementClass

.g:		align	4
		db	"roup",0,0
		align	4
		dd	groupClass

		align	4
elementMap:	dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,.a+1,1,.c+1,1,.e+1,1,1,1,.i+1,1,1,1,1,1,1
		dd	1,1,.r+1,1,.t+1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1

		align	4
.a:		db	"ttribute",0,0
		align	4
		dd	attributeClass

		align	4
.t:		db	"ext",0,0
		align	4
		dd	textClass

.c:		align	4
		db	"ollection",0,0
		align	4
		dd	collectionClass

.e:		align	4
		db	"lement",0,0
		align	4
		dd	elementClass

.i:		align	4
		db	"nclude",0,0
		align	4
		dd	includeClass

.r:		align	4
		db	"eference",0,0
		align	4
		dd	referenceClass
;[cf]
;[of]:name=
		align	4
nameAttr:	dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,.name+1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1

		align	4
.name:		db	"ame",0
		dd	Element.sizeof + 0 * Attribute.sizeof

;[cf]
;[of]:name= ignore=
		align	4
nameIgnoreAttr:	
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,.ignore+1,1,1,1,1,.name+1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1

		align	4
.name:		db	"ame",0
		dd	Element.sizeof + 0 * Attribute.sizeof

		align	4
.ignore:	db	"gnore",0
		dd	Element.sizeof + 1 * Attribute.sizeof

;[cf]
;[of]:name= ignore= id= type=

		align	4
nameAndTypeAttr:
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,.i,1,1,1,1,.name+1,1
		dd	1,1,1,1,.type+1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1

.i:		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,.id+1,1,1,.ignore+1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
		dd	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1

		align	4
.name:		db	"ame",0
		dd	Element.sizeof + 0 * Attribute.sizeof

		align	4
.ignore		db	"nore",0
		dd	Element.sizeof + 1 * Attribute.sizeof

		align	4
.type:		db	"ype",0
		dd	Element.sizeof + 2 * Attribute.sizeof

		align	4
.id:		db	0
		dd	Element.sizeof + 3 * Attribute.sizeof
;[cf]

;[of]:Element Names
schemaName	db	"schema",0
documentName	db	"document",0
attributeName	db	"attribute",0
textName	db	"text",0
collectionName	db	"collection",0
elementName	db	"element",0
referenceName	db	"reference",0
includeName	db	"include",0
groupName	db	"group",0
invalidName	db	"?",0

textValue	db	"text",0
mixedValue	db	"mixed",0

yes		db	"yes",0
no		db	"no",0
;[cf]
;[cf]
;[of]:Atoms
atomTable	dd	DOCTYPEName
		dd	ELEMENTName
		dd	ATTLISTName
		dd	PCDATAName
		dd	IMPLIEDName
		dd	REQUIREDName
		dd	FIXEDName
		dd	NDATAName

		dd	CDATAName
		dd	IDName
		dd	IDREFName
		dd	IDREFSName
		dd	ENTITYName
		dd	ENTITIESName
		dd	NMTOKENName
		dd	NMTOKENSName
		dd	NOTATIONName
		
		dd	versionName
		dd	encodingName
		dd	standaloneName
		dd	0
	
DOCTYPEName	db	"DOCTYPE",0
ELEMENTName	db	"ELEMENT",0
ATTLISTName	db	"ATTLIST",0
PCDATAName	db	"PCDATA",0
IMPLIEDName	db	"IMPLIED",0
REQUIREDName	db	"REQUIRED",0
FIXEDName	db	"FIXED",0
NDATAName	db	"NDATA",0

CDATAName	db	"CDATA",0
IDName		db	"ID",0
IDREFName	db	"IDREF",0
IDREFSName	db	"IDREFS",0
ENTITYName	db	"ENTITY",0
ENTITIESName	db	"ENTITIES",0
NMTOKENName	db	"NMTOKEN",0
NMTOKENSName	db	"NMTOKENS",0
NOTATIONName	db	"NOTATION",0

versionName	db	"version",0
encodingName	db	"encoding",0
standaloneName	db	"standalone",0
;[cf]
;[cf]
;[of]:BSS
section	'.asmdata' writeable

mallocFunction	rd	1
freeFunction	rd	1

;[cf]
