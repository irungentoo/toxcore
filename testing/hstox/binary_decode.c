#include "methods.h"

#include "byteswap.h"
#include "packet_kinds.h"

#include "../../toxcore/DHT.h"


static void decode_bytestring(msgpack_object_bin args, msgpack_packer *res,
                              int64_t min_length)
{
    int64_t length;
    uint64_t tmp;

    SUCCESS {
        if (args.size < sizeof(uint64_t))
        {
            // Not enough space to even fit the size.
            msgpack_pack_nil(res);
            return;
        }

        memcpy(&tmp, args.ptr, sizeof(uint64_t));
        length = be64toh(tmp);

        // TODO(iphydf): Get rid of this case if/when
        // https://github.com/kolmodin/binary/issues/127 is fixed. This is a
        // workaround for a Haskell library bug. Our implementation here without
        // the special case for negative length, and instead interpreting the
        // length as unsigned integer, was correct.
        if (length < 0)
        {
            length = 0;
        }

        if (args.size >= sizeof(uint64_t) && args.size == length + sizeof(uint64_t))
        {
            if (length < min_length) {
                // CipherTexts need at least a MAC.
                msgpack_pack_nil(res);
                return;
            }

            msgpack_pack_bin(res, args.size - sizeof(uint64_t));
            msgpack_pack_bin_body(res, args.ptr + sizeof(uint64_t), args.size - sizeof(uint64_t));
        } else {
            msgpack_pack_nil(res);
        }
    }
}


METHOD(bin, Binary_decode, CipherText)
{
    decode_bytestring(args, res, CRYPTO_MAC_SIZE);
    return 0;
}

METHOD(bin, Binary_decode, DhtPacket)
{
    return pending;
}

METHOD(bin, Binary_decode, HostAddress)
{
    return pending;
}

METHOD(bin, Binary_decode, Word64)
{
    return pending;
}

METHOD(bin, Binary_decode, Key_PublicKey)
{
    return pending;
}

METHOD(bin, Binary_decode, KeyPair)
{
    SUCCESS {
        if (args.size != 64)
        {
            msgpack_pack_nil(res);
        } else {
            msgpack_pack_array(res, 2);
            msgpack_pack_bin(res, 32);
            msgpack_pack_bin_body(res, args.ptr, 32);
            msgpack_pack_bin(res, 32);
            msgpack_pack_bin_body(res, args.ptr + 32, 32);
        }
    }

    return 0;
}

METHOD(bin, Binary_decode, NodeInfo)
{
    uint16_t    data_processed;
    Node_format node;
    int len = unpack_nodes(&node, 1, &data_processed, (uint8_t const *)args.ptr, args.size, 1);

    bool ip6_node = node.ip_port.ip.family == AF_INET6 || node.ip_port.ip.family == TCP_INET6;
    bool tcp      = node.ip_port.ip.family == TCP_INET || node.ip_port.ip.family == TCP_INET6;

    uint16_t port  = ntohs(node.ip_port.port);
    uint32_t ip4   = ntohl(node.ip_port.ip.ip4.uint32);
    uint32_t ip6_0 = ntohl(node.ip_port.ip.ip6.uint32[0]);
    uint32_t ip6_1 = ntohl(node.ip_port.ip.ip6.uint32[1]);
    uint32_t ip6_2 = ntohl(node.ip_port.ip.ip6.uint32[2]);
    uint32_t ip6_3 = ntohl(node.ip_port.ip.ip6.uint32[3]);

    SUCCESS {
        if (len > 0 && data_processed > 0 && data_processed == args.size)
        {
            msgpack_pack_array(res, 3);
            msgpack_pack_uint8(res, tcp);
            msgpack_pack_array(res, 2);
            msgpack_pack_array(res, 2);
            msgpack_pack_uint8(res, ip6_node);

            if (ip6_node) {
                msgpack_pack_array(res, 4);
                msgpack_pack_uint32(res, ip6_0);
                msgpack_pack_uint32(res, ip6_1);
                msgpack_pack_uint32(res, ip6_2);
                msgpack_pack_uint32(res, ip6_3);
            } else {
                msgpack_pack_uint32(res, ip4);
            }

            msgpack_pack_uint16(res, port);
            msgpack_pack_bin(res, CRYPTO_PUBLIC_KEY_SIZE);
            msgpack_pack_bin_body(res, &node.public_key, CRYPTO_PUBLIC_KEY_SIZE);
        } else {
            msgpack_pack_nil(res);
        }
    }

    return 0;
}

METHOD(bin, Binary_decode, NodesRequest)
{
    return pending;
}

METHOD(bin, Binary_decode, NodesResponse)
{
    return pending;
}

METHOD(bin, Binary_decode, Packet_Word64)
{
    return pending;
}

METHOD(bin, Binary_decode, PacketKind)
{
    SUCCESS {
        if (args.size != 1)
        {
            msgpack_pack_nil(res);
        } else {
            uint8_t kind = args.ptr[0];
            size_t  i;

            for (i = 0; i < sizeof packet_kinds / sizeof *packet_kinds; i++)
            {
                if (packet_kinds[i] == kind) {
                    msgpack_pack_fix_uint8(res, i);
                    return 0;
                }
            }

            // Packet kind not found => error.
            msgpack_pack_nil(res);
        }
    }
    return 0;
}

METHOD(bin, Binary_decode, PingPacket)
{
    return pending;
}

METHOD(bin, Binary_decode, PlainText)
{
    decode_bytestring(args, res, 0);
    return 0;
}

METHOD(bin, Binary_decode, PortNumber)
{
    SUCCESS {
        if (args.size == 2)
        {
            uint16_t tmp;
            memcpy(&tmp, args.ptr, 2);
            uint16_t port = ntohs(tmp);
            msgpack_pack_uint16(res, port);
        } else {
            msgpack_pack_nil(res);
        }
    }

    return 0;
}

METHOD(bin, Binary_decode, RpcPacket_Word64)
{
    return pending;
}

METHOD(bin, Binary_decode, SocketAddress)
{
    return pending;
}

METHOD(bin, Binary_decode, TransportProtocol)
{
    return pending;
}

METHOD(array, Binary, decode)
{
    CHECK_SIZE(args, 2);
    CHECK_TYPE(args.ptr[0], MSGPACK_OBJECT_STR);
    CHECK_TYPE(args.ptr[1], MSGPACK_OBJECT_BIN);

    msgpack_object_str type = args.ptr[0].via.str;
#define DISPATCH(TYPE)                                                                \
    if (type.size == sizeof #TYPE - 1 && method_cmp(type.ptr, #TYPE, type.size) == 0) \
        return Binary_decode_##TYPE(args.ptr[1].via.bin, res)
    DISPATCH(CipherText);
    DISPATCH(DhtPacket);
    DISPATCH(HostAddress);
    DISPATCH(Word64);
    DISPATCH(Key_PublicKey);
    DISPATCH(KeyPair);
    DISPATCH(NodeInfo);
    DISPATCH(NodesRequest);
    DISPATCH(NodesResponse);
    DISPATCH(Packet_Word64);
    DISPATCH(PacketKind);
    DISPATCH(PingPacket);
    DISPATCH(PlainText);
    DISPATCH(PortNumber);
    DISPATCH(RpcPacket_Word64);
    DISPATCH(SocketAddress);
    DISPATCH(TransportProtocol);
#undef DISPATCH

    return unimplemented;
}
