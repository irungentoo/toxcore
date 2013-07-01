/****************************************************************************
*                                                                           *
* asm-xml.h                                                                 *
*                                                                           *
* Copyright (C) 2007-08 Marc Kerbiquet                                      *
*                                                                           *
****************************************************************************/

#ifdef WIN32
  #define ACC __cdecl
#else
  #define ACC
#endif

#ifdef __cplusplus
extern "C" {
#endif

//-----------------------------------------------------------------------------
// Error Codes
//-----------------------------------------------------------------------------
#define RC_OK                          0 // everything is ok
#define RC_MEMORY                      1 // out of memory

#define RC_EMPTY_NAME                 10 // name empty or not defined
#define RC_ATTR_DEFINED               11 // attribute already defined
#define RC_ELEM_DEFINED               12 // element already defined
#define RC_SCHEMA_EMPTY               13 // schema does not contains a document
#define RC_DOCUMENT_DEFINED           14 // schema contains more than one document
#define RC_UNDEFINED_CLASS            15 // can't find collection in reference
#define RC_UNDEFINED_GROUP            16 // can't find a group in include
#define RC_INVALID_ID                 17 // id is not a valid number
#define RC_INVALID_IGNORE             18 // ignore is not 'yes' or 'no'

#define RC_INVALID_ENTITY_REFERENCE   20 // must be amp, quot, lt, gt, or apos
#define RC_UNEXPECTED_END             21 // found last char too early
#define RC_INVALID_CHAR               22 // wrong char
#define RC_OVERFLOW                   23 // number to big in char reference
#define RC_NO_START_TAG               24 // xml does not start with a tag
#define RC_TAG_MISMATCH               25 // invalid close tag
#define RC_INVALID_TAG                26 // invalid root element
#define RC_INVALID_ATTRIBUTE          27 // unknown attribute
#define RC_INVALID_PI                 28 // invalid processing instruction (<?xml)
#define RC_INVALID_DOCTYPE            29 // duplicate doctype or after main element
#define RC_VERSION_EXPECTED           30 // version is missing in xml declaration

//-----------------------------------------------------------------------------
// Structures
//-----------------------------------------------------------------------------
typedef struct AXElement      AXElement       ;
typedef struct AXAttribute    AXAttribute     ;
typedef struct AXElementClass AXElementClass  ;
typedef struct AXParseContext AXParseContext  ;
typedef struct AXClassContext AXClassContext  ;

struct AXElementClass
{
  int               offset        ; // Offset of the element in attribute list
  char*             name          ; // Name of the element (not zero terminated)
  char*             nameLimit     ; // End of the name of the element
  unsigned int      size          ; // size in bytes of an element of this class
  unsigned int      id            ; // container, text or mixed
  unsigned int      type          ; // container, text or mixed
  unsigned int      propertyCount ; // number of attributes and text elements
  unsigned int      childCount    ; // number of child classes
  int*              attributes    ; // (internal) attribute map
  int*              elements      ; // (internal) element map
  AXElementClass**  children      ; // The list of child classes.
                                    // The order is the one defined in the class
                                    // definition file.
  int               reserved      ;
  void*             reserved2     ;
};

struct AXClassContext
{
  void*             base          ;
  void*             limit         ;
  void*             chunks        ;
  int               chunkSize     ;
  int               errorCode     ;
  int               line          ;
  int               column        ;
  AXElementClass**  classes       ; // all global classes
  AXElementClass*   rootClass     ; // the root class
  AXElement*        rootElement   ;
};

struct AXAttribute
{
  const char*       begin         ; // the value (not zero terminated)
                                    // This slot can also contain an element if
                                    // a <element> has been defined in schema;
                                    // use ax_getElement() to retrieve it.
  const char*       limit         ; // the end of the value
};

struct AXElement
{
  int               id            ; // the class of the element
  AXElement*        nextSibling   ; // the next sibling element
  AXElement*        firstChild    ; // the first child element
  AXElement*        lastChild     ; // the last child element
  AXAttribute       reserved      ; // do not use
  AXAttribute       attributes[1] ; // the array of attributes - there is 
                                    // no bound checking in C
};

struct AXParseContext
{
  void*             base          ;
  void*             limit         ;
  void*             chunks        ;
  int               chunkSize     ;
  int               errorCode     ;
  const char*       source        ;
  const char*       current       ;
  int               line          ;
  int               column        ;
  AXElement*        root          ;
  AXAttribute       version       ;
  AXAttribute       encoding      ;
  int               strict        ;
  int               reserved1     ;
  AXElement         reserved2     ;
};

//-----------------------------------------------------------------------------
// Functions
//-----------------------------------------------------------------------------

extern 
void            ACC ax_initialize            (void*             mallocFun, 
                                              void*             freeFun);
extern 
int             ACC ax_initializeParser      (AXParseContext*   context, 
                                              unsigned int      chunkSize);
extern 
int             ACC ax_releaseParser         (AXParseContext*   context);
extern 
AXElement*      ACC ax_parse                 (AXParseContext*   context, 
                                              const char*       source,
                                              AXElementClass*   type,
                                              int               strict);
extern 
int             ACC ax_initializeClassParser (AXClassContext*   context);
extern 
int             ACC ax_releaseClassParser    (AXClassContext*   context);
extern 
AXElementClass* ACC ax_classFromElement      (AXElement*        e,
                                              AXClassContext*   context);
extern 
AXElementClass* ACC ax_classFromString       (const char*       source, 
                                              AXClassContext*   context);

#define ax_getElement(element, index) ((AXElement*)element->attributes[index].begin)
#define ax_getAttribute(element, index) (&element->attributes[index])


#ifdef __cplusplus
}
#endif
