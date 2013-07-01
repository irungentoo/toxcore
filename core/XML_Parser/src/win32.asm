;[c]asm-xml.asm - Asm XML Parser
;[c]
;[c]Compile this file with fasm.
;[c]
format MS COFF

include "asm-xml.asm"

;[c]
;[c]Public Functions
;[c]
public _initialize		as "_ax_initialize"
public _initializeParser	as "_ax_initializeParser"
public _releaseParser		as "_ax_releaseParser"
public _parse			as "_ax_parse"
public _initializeClassParser	as "_ax_initializeClassParser"
public _releaseClassParser	as "_ax_releaseClassParser"
public _classFromElement	as "_ax_classFromElement"
public _classFromString		as "_ax_classFromString"
