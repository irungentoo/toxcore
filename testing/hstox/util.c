#include "util.h"

#include <stdarg.h>

char const *type_name(msgpack_object_type type)
{
    switch (type) {
        case MSGPACK_OBJECT_NIL:
            return "nil";

        case MSGPACK_OBJECT_BOOLEAN:
            return "boolean";

        case MSGPACK_OBJECT_POSITIVE_INTEGER:
            return "positive_integer";

        case MSGPACK_OBJECT_NEGATIVE_INTEGER:
            return "negative_integer";

        case MSGPACK_OBJECT_FLOAT:
            return "float";

        case MSGPACK_OBJECT_STR:
            return "str";

        case MSGPACK_OBJECT_ARRAY:
            return "array";

        case MSGPACK_OBJECT_MAP:
            return "map";

        case MSGPACK_OBJECT_BIN:
            return "bin";

        case MSGPACK_OBJECT_EXT:
            return "ext";
    }

    return "<unknown type>";
}

int msgpack_pack_string(msgpack_packer *pk, char const *str)
{
    size_t len = strlen(str);
    msgpack_pack_str(pk, len);
    return msgpack_pack_str_body(pk, str, len);
}

int msgpack_pack_vstringf(msgpack_packer *pk, char const *fmt, va_list ap)
{
    char buf[1024];
    vsnprintf(buf, sizeof buf, fmt, ap);
    return msgpack_pack_string(pk, buf);
}

int msgpack_pack_stringf(msgpack_packer *pk, char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int res = msgpack_pack_vstringf(pk, fmt, ap);
    va_end(ap);
    return res;
}

char const *ssprintf(char const *fmt, ...)
{
    static char buf[1024];

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    return buf;
}
