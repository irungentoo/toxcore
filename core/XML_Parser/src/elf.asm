;[c]asm-xml.asm - Asm XML Parser
;[c]
;[c]Compile this file with fasm.
;[c]
format ELF

include "asm-xml.asm"

;[c]
;[c]Public Functions
;[c]
public _initialize		as "ax_initialize"
public _initializeParser	as "ax_initializeParser"
public _releaseParser		as "ax_releaseParser"
public _parse			as "ax_parse"
public _initializeClassParser	as "ax_initializeClassParser"
public _releaseClassParser	as "ax_releaseClassParser"
public _classFromElement	as "ax_classFromElement"
public _classFromString		as "ax_classFromString"
