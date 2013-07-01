///////////////////////////////////////////////////////////////////////////////
//
// Friend List Parser
//
///////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "asm-xml.h"

static const int  chunkSize = 16*1024*1024; // 16Mk
static const char schemaFilename[] = "schema.xml";
static const char xmlFilename[]    = "friends.xml";

char buffer[65536];

///////////////////////////////////////////////////////////////////////////////
// Print an attribute / text value
///////////////////////////////////////////////////////////////////////////////
const char* asString(AXAttribute* attr)
{
  const char* start = attr->begin;
  const char* limit = attr->limit;
  size_t size = limit - start;
  memcpy(buffer, start, size);
  buffer[size] = 0;
  return buffer;
}

///////////////////////////////////////////////////////////////////////////////
// Print an error code from the parser
///////////////////////////////////////////////////////////////////////////////
void printAsmXmlError(AXParseContext* context)
{
  fprintf(stderr, "Error (%d,%d): %d\n", context->line, context->column, context->errorCode);
}

///////////////////////////////////////////////////////////////////////////////
// Read Schema Definition
///////////////////////////////////////////////////////////////////////////////
AXElementClass* readClass(const char* filename, AXClassContext* classContext)
{
  FILE*    f;
  size_t  size;

  f = fopen(filename, "rb");
  if( f == NULL )
  {
    fprintf(stderr, "can't open schema '%s'\n", filename);
    return NULL;
  }
  size = fread(buffer, 1, 65535, f);
  buffer[size] = 0;
  fclose(f);

  // Parse the string and build the class
  return ax_classFromString(buffer, classContext);
}

///////////////////////////////////////////////////////////////////////////////
// Read Document
///////////////////////////////////////////////////////////////////////////////
AXElement* readDocument(const char*     filename,
                        AXParseContext* parseContext,
                        AXElementClass* clazz)
{
  FILE*    f;
  size_t  size;

  f = fopen(filename, "rb");
  if( f == NULL )
  {
    fprintf(stderr, "can't open file '%s'\n", filename);
    return NULL;
  }
  size = fread(buffer, 1, 65535, f);
  buffer[size] = 0;
  fclose(f);

  // Parse the string and build the class
  return ax_parse(parseContext, buffer, clazz, 1);
}

///////////////////////////////////////////////////////////////////////////////
// main
///////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
  int             res;
  AXClassContext  classContext;
  AXParseContext  parseContext;
  AXElementClass* friendClass;
  AXElement*      friends;
  AXElement*      friend;

  // Initialize the AsmXml library
  //
  // Pass the malloc() and free() functions
  //
  ax_initialize(malloc, free);

  // Initialize the class context
  //
  // It can store one or more classes. Classes read with this
  // context are kept in memory as long as it is not released.
  //
  res = ax_initializeClassParser(&classContext);
  // An error while initialization means that allocation failed.
  // It should never happen since it allocates only 4K.
  if( res != 0 )
    return 1;

  // Read the schema and compile it
  //
  friendClass = readClass(schemaFilename, &classContext);
  if( friendClass == NULL )
    return 1;

  // Initialize the parser
  //
  // Documents read with this parser will stay in memory as long as
  // the parser is not released.
  //
  // The choice of the chunk size is very important since the
  // performance can be affected by this value. The parser allocates
  // memory by chunks to reduce calls to malloc that can be very slow.
  // The ideal value is around 50% of the source XML to process.
  //
  res = ax_initializeParser(&parseContext, chunkSize);
  // An error while initialization means that initial allocation failed.
  if( res != 0 )
    return 1;

  // Read the file and parse it
  //
  friends = readDocument(xmlFilename, &parseContext, friendClass);
  if( friends == NULL )
  {
    printAsmXmlError(&parseContext);
    return 1;
  }

  // Enumerate child elements
  friend = friends->firstChild;
  while( friend )
  {
    printf("================================\n");
    printf("Friend ID: %s\n", asString(&friend->attributes[0]));
    printf("Name: %s\n", asString(&friend->attributes[1]));
    printf("UserID: %s\n", asString(&friend->attributes[2]));
    friend = friend->nextSibling;
    printf("================================\n");
  }

  // Release the document and its class
  ax_releaseParser(&parseContext);
  ax_releaseClassParser(&classContext);
  return 0;
}
