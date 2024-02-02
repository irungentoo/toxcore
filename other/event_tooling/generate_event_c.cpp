// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2023-2024 The TokTok team.

// this file can be used to generate event.c files
// requires c++17

#include <fstream>
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
#include <variant>
#include <map>

std::string str_tolower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}

std::string str_toupper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::toupper(c); });
    return s;
}

std::string output_folder = "out";

struct EventTypeTrivial {
    std::string type; // eg uint32_t
    std::string name; // eg friend_number
};

struct EventTypeByteRange {
    // type is always uint8_t * for data AND uint32_t for length
    std::string name_data; // eg data
    std::string name_length; // eg data_length
    std::string name_length_cb; // eg length // TODO: merge with normal?
};

// TODO: EventTypeByteArray

using EventType = std::variant<EventTypeTrivial, EventTypeByteRange>;

// helper type for the visitor #4
template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
// explicit deduction guide (not needed as of C++20)
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

std::string bin_pack_name_from_type(const std::string& type) {
    if (type == "uint64_t") {
        return "bin_pack_u64";
    } else if (type == "uint32_t") {
        return "bin_pack_u32";
    } else if (type == "uint16_t") {
        return "bin_pack_u16";
    } else if (type == "uint8_t") {
        return "bin_pack_u8";
    } else if (type == "bool") {
        return "bin_pack_bool";
    } else if (type == "Tox_User_Status") {
        return "tox_user_status_pack";
    } else if (type == "Tox_Conference_Type") {
        return "tox_conference_type_pack";
    } else if (type == "Tox_Message_Type") {
        return "tox_message_type_pack";
    } else if (type == "Tox_File_Control") {
        return "tox_file_control_pack";
    } else if (type == "Tox_Connection") {
        return "tox_connection_pack";
    } else if (type == "Tox_Group_Privacy_State") {
        return "tox_group_privacy_state_pack";
    } else if (type == "Tox_Group_Voice_State") {
        return "tox_group_voice_state_pack";
    } else if (type == "Tox_Group_Topic_Lock") {
        return "tox_group_topic_lock_pack";
    } else if (type == "Tox_Group_Join_Fail") {
        return "tox_group_join_fail_pack";
    } else if (type == "Tox_Group_Mod_Event") {
        return "tox_group_mod_event_pack";
    } else if (type == "Tox_Group_Exit_Type") {
        return "tox_group_exit_type_pack";
    } else {
        std::cerr << "unknown type " << type << "\n";
        exit(1);
        return "bin_pack_u32";
    }
}
std::string bin_unpack_name_from_type(const std::string& type) {
    if (type == "uint64_t") {
        return "bin_unpack_u64";
    } else if (type == "uint32_t") {
        return "bin_unpack_u32";
    } else if (type == "uint16_t") {
        return "bin_unpack_u16";
    } else if (type == "uint8_t") {
        return "bin_unpack_u8";
    } else if (type == "bool") {
        return "bin_unpack_bool";
    } else if (type == "Tox_User_Status") {
        return "tox_user_status_unpack";
    } else if (type == "Tox_Conference_Type") {
        return "tox_conference_type_unpack";
    } else if (type == "Tox_Message_Type") {
        return "tox_message_type_unpack";
    } else if (type == "Tox_File_Control") {
        return "tox_file_control_unpack";
    } else if (type == "Tox_Connection") {
        return "tox_connection_unpack";
    } else if (type == "Tox_Group_Privacy_State") {
        return "tox_group_privacy_state_unpack";
    } else if (type == "Tox_Group_Voice_State") {
        return "tox_group_voice_state_unpack";
    } else if (type == "Tox_Group_Topic_Lock") {
        return "tox_group_topic_lock_unpack";
    } else if (type == "Tox_Group_Join_Fail") {
        return "tox_group_join_fail_unpack";
    } else if (type == "Tox_Group_Mod_Event") {
        return "tox_group_mod_event_unpack";
    } else if (type == "Tox_Group_Exit_Type") {
        return "tox_group_exit_type_unpack";
    } else {
        std::cerr << "unknown type " << type << "\n";
        exit(1);
        // assume enum -> u32
        return "bin_unpack_u32";
    }
}

void generate_event_impl(const std::string& event_name, const std::vector<EventType>& event_types) {
    const std::string event_name_l = str_tolower(event_name);
    std::string file_name = output_folder + "/" + event_name_l + ".c";

    std::ofstream f(file_name);
    if (!f.good()) {
        std::cerr << "error opening file to write " << file_name << "\n";
        exit(1);
    }

    bool need_stdlib_h = false;
    bool need_string_h = false;
    bool need_tox_unpack_h = false;
    for (const auto& t : event_types) {
        std::visit(
            overloaded{
                [&](const EventTypeTrivial& t) {
                    if (bin_unpack_name_from_type(t.type).rfind("tox_", 0) == 0) {
                        need_tox_unpack_h = true;
                    }
                },
                [&](const EventTypeByteRange&) {
                    need_stdlib_h = true;
                    need_string_h = true;
                }
            },
            t
        );
    }

    f << R"(/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2024 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>)";
    if (need_stdlib_h) {
        f << R"(
#include <stdlib.h>)";
    }
    if (need_string_h) {
        f << R"(
#include <string.h>)";
    }
    f << R"(

#include "../attributes.h"
#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../ccompat.h"
#include "../mem.h"
#include "../tox.h"
#include "../tox_events.h")";
    if (need_tox_unpack_h) {
        f << R"(
#include "../tox_pack.h"
#include "../tox_unpack.h")";
    }
    f << R"(

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

)";

    // gen struct
    f << "struct Tox_Event_" << event_name << " {\n";
    for (const auto& t : event_types) {
        std::visit(
            overloaded{
                [&](const EventTypeTrivial& t) {
                    f << "    " << t.type << " " << t.name << ";\n";
                },
                [&](const EventTypeByteRange& t) {
                    f << "    " << "uint8_t" << " *" << t.name_data << ";\n";
                    f << "    " << "uint32_t" << " " << t.name_length << ";\n";
                }
            },
            t
        );
    }
    f << "};\n\n";

    // gen setters and getters
    for (const auto& t : event_types) {
        // setter
        std::visit(
            overloaded{
                [&](const EventTypeTrivial& t) {
                    f << "non_null()\n";
                },
                [&](const EventTypeByteRange& t) {
                    f << "non_null(1) nullable(2)\n";
                }
            },
            t
        );
        f << "static " << (t.index() == 0 ? "void" : "bool") << " tox_event_" << event_name_l << "_set_";
        std::visit(
            overloaded{
                [&](const EventTypeTrivial& t) {
                    f << t.name;
                },
                [&](const EventTypeByteRange& t) {
                    f << t.name_data;
                }
            },
            t
        );
        f << "(Tox_Event_" << event_name << " *" << event_name_l << ",\n";
        f << "        ";
        std::visit(
            overloaded{
                [&](const EventTypeTrivial& t) {
                    f << t.type << " " << t.name << ")\n";
                },
                [&](const EventTypeByteRange& t) {
                    f << "const uint8_t *" << t.name_data << ", uint32_t " << t.name_length << ")\n";
                }
            },
            t
        );
        f << "{\n    assert(" << event_name_l << " != nullptr);\n";
        std::visit(
            overloaded{
                [&](const EventTypeTrivial& t) {
                    f << "    " << event_name_l << "->" << t.name << " = " << t.name << ";\n";
                },
                [&](const EventTypeByteRange& t) {
                    f << "\n    if (" << event_name_l << "->" << t.name_data << " != nullptr) {\n";
                    f << "        free(" << event_name_l << "->" << t.name_data << ");\n";
                    f << "        " << event_name_l << "->" << t.name_data << " = nullptr;\n";
                    f << "        " << event_name_l << "->" << t.name_length << " = 0;\n";
                    f << "    }\n\n";
                    f << "    if (" << t.name_data << " == nullptr) {\n";
                    f << "        assert(" << t.name_length << " == 0);\n";
                    f << "        return true;\n    }\n\n";
                    f << "    uint8_t *" << t.name_data << "_copy = (uint8_t *)malloc(" << t.name_length << ");\n\n";
                    f << "    if (" << t.name_data << "_copy == nullptr) {\n";
                    f << "        return false;\n    }\n\n";
                    f << "    memcpy(" << t.name_data << "_copy, " << t.name_data << ", " << t.name_length << ");\n";
                    f << "    " << event_name_l << "->" << t.name_data << " = " << t.name_data << "_copy;\n";
                    f << "    " << event_name_l << "->" << t.name_length << " = " << t.name_length << ";\n";
                    f << "    return true;\n";
                }
            },
            t
        );
        f << "}\n";

        // getter
        std::visit(
            overloaded{
                [&](const EventTypeTrivial& t) {
                    //f << "non_null()\n"; // TODO: is this missing in the original?
                    f << t.type << " tox_event_" << event_name_l << "_get_" << t.name;
                    f << "(const Tox_Event_" << event_name << " *" << event_name_l << ")\n";
                    f << "{\n    assert(" << event_name_l << " != nullptr);\n";
                    f << "    return " << event_name_l << "->" << t.name << ";\n}\n\n";
                },
                [&](const EventTypeByteRange& t) {
                    //f << "non_null()\n"; // TODO: is this missing in the original?
                    f << "uint32_t tox_event_" << event_name_l << "_get_" << t.name_length;
                    f << "(const Tox_Event_" << event_name << " *" << event_name_l << ")\n";
                    f << "{\n    assert(" << event_name_l << " != nullptr);\n";
                    f << "    return " << event_name_l << "->" << t.name_length << ";\n}\n";
                    f << "const uint8_t *tox_event_" << event_name_l << "_get_" << t.name_data;
                    f << "(const Tox_Event_" << event_name << " *" << event_name_l << ")\n";
                    f << "{\n    assert(" << event_name_l << " != nullptr);\n";
                    f << "    return " << event_name_l << "->" << t.name_data << ";\n}\n\n";
                }
            },
            t
        );
    }


    // gen contruct
    f << "non_null()\n";
    f << "static void tox_event_" << event_name_l << "_construct(Tox_Event_" << event_name << " *" << event_name_l << ")\n{\n";
    // TODO: initialize all members properly
    // TODO: check if _NONE is universal
    // str_toupper(
    f << "    *" << event_name_l << " = (Tox_Event_" << event_name << ") {\n        0\n    };\n}\n";

    // gen destruct
    f << "non_null()\n";
    f << "static void tox_event_" << event_name_l << "_destruct(Tox_Event_" << event_name << " *" << event_name_l << ", const Memory *mem)\n{\n";
    size_t data_count = 0;
    for (const auto& t : event_types) {
        std::visit(
            overloaded{
                [&](const EventTypeTrivial&) {},
                [&](const EventTypeByteRange& t) {
                    f << "    free(" << event_name_l << "->" << t.name_data << ");\n";
                    //f << "    mem->funcs->free(mem->obj, " << event_name_l << "->" << t.name_data << ");\n";
                    data_count++;
                }
            },
            t
        );
    }
    if (data_count == 0) {
        f << "    return;\n";
    }
    f << "}\n\n";

    // pack
    f << "bool tox_event_" << event_name_l << "_pack(\n";
    f << "    const Tox_Event_" << event_name << " *event, Bin_Pack *bp)\n{\n";

    bool return_started = false;

    if (event_types.size() > 1) {
        f << "    return bin_pack_array(bp, " << event_types.size() << ")";
        return_started = true;
    }

    for (const auto& t : event_types) {
        if (return_started) {
            f << "\n           && ";
        } else {
            f << "    return ";
        }

        std::visit(
            overloaded{
                [&](const EventTypeTrivial& t) {
                    f << bin_pack_name_from_type(t.type);
                    if (t.type.rfind("Tox_", 0) == 0) {
                        f << "(event->" << t.name << ", bp)";
                    } else {
                        f << "(bp, event->" << t.name << ")";
                    }
                },
                [&](const EventTypeByteRange& t) {
                    f << "bin_pack_bin(bp, event->" << t.name_data << ", event->" << t.name_length << ")";
                }
            },
            t
        );
    }
    f << ";\n}\n\n";

    // unpack
    f << "non_null()\n";
    f << "static bool tox_event_" << event_name_l << "_unpack_into(\n";
    f << "    Tox_Event_" << event_name << " *event, Bin_Unpack *bu)\n{\n";
    f << "    assert(event != nullptr);\n";
    if (event_types.size() > 1) {
        f << "    if (!bin_unpack_array_fixed(bu, " << event_types.size() << ", nullptr)) {\n        return false;\n    }\n\n";
    }

    bool first = true;
    for (const auto& t : event_types) {
        if (first) {
            f << "    return ";
        } else {
            f << "\n           && ";
        }
        std::visit(
            overloaded{
                [&](const EventTypeTrivial& t) {
                    f << bin_unpack_name_from_type(t.type);
                    if (t.type.rfind("Tox_", 0) == 0) {
                        f << "(&event->" << t.name << ", bu)";
                    } else {
                        f << "(bu, &event->" << t.name << ")";
                    }
                },
                [&](const EventTypeByteRange& t) {
                    f << "bin_unpack_bin(bu, &event->" << t.name_data << ", &event->" << t.name_length << ")";
                }
            },
            t
        );
        first = false;
    }
    f << ";\n}\n";

    f << R"(
/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

)";

    f << "const Tox_Event_" << event_name << " *tox_event_get_" << event_name_l << "(const Tox_Event *event)\n{\n";
    f << "    return event->type == TOX_EVENT_" << str_toupper(event_name) << " ? event->data." << event_name_l << " : nullptr;\n}\n\n";

    // new
    f << "Tox_Event_" << event_name << " *tox_event_" << event_name_l << "_new(const Memory *mem)\n{\n";
    f << "    Tox_Event_" << event_name << " *const " << event_name_l << " =\n";
    f << "        (Tox_Event_" << event_name << " *)mem_alloc(mem, sizeof(Tox_Event_" << event_name << "));\n\n";
    f << "    if (" << event_name_l << " == nullptr) {\n        return nullptr;\n    }\n\n";
    f << "    tox_event_" << event_name_l << "_construct(" << event_name_l << ");\n";
    f << "    return " << event_name_l << ";\n}\n\n";

    // free
    f << "void tox_event_" << event_name_l << "_free(Tox_Event_" << event_name << " *" << event_name_l << ", const Memory *mem)\n{\n";
    f << "    if (" << event_name_l << " != nullptr) {\n";
    f << "        tox_event_" << event_name_l << "_destruct(" << event_name_l << ", mem);\n    }\n";
    f << "    mem_delete(mem, " << event_name_l << ");\n}\n\n";

    // add
    f << "non_null()\n";
    f << "static Tox_Event_" << event_name << " *tox_events_add_" << event_name_l << "(Tox_Events *events, const Memory *mem)\n{\n";
    f << "    Tox_Event_" << event_name << " *const " << event_name_l << " = tox_event_" << event_name_l << "_new(mem);\n\n";
    f << "    if (" << event_name_l << " == nullptr) {\n";
    f << "        return nullptr;\n    }\n\n";
    f << "    Tox_Event event;\n";
    f << "    event.type = TOX_EVENT_" << str_toupper(event_name) << ";\n";
    f << "    event.data." << event_name_l << " = " << event_name_l << ";\n\n";
    f << "    tox_events_add(events, &event);\n";
    f << "    return " << event_name_l << ";\n}\n\n";

    // unpack
    f << "bool tox_event_" << event_name_l << "_unpack(\n";
    f << "    Tox_Event_" << event_name << " **event, Bin_Unpack *bu, const Memory *mem)\n{\n";
    f << "    assert(event != nullptr);\n";
    f << "    assert(*event == nullptr);\n";
    f << "    *event = tox_event_" << event_name_l << "_new(mem);\n\n";
    f << "    if (*event == nullptr) {\n        return false;\n    }\n\n";
    f << "    return tox_event_" << event_name_l << "_unpack_into(*event, bu);\n}\n\n";

    // alloc
    f << "non_null()\n";
    f << "static Tox_Event_" << event_name << " *tox_event_" << event_name_l << "_alloc(void *user_data)\n{\n";
    f << "    Tox_Events_State *state = tox_events_alloc(user_data);\n";
    f << "    assert(state != nullptr);\n\n";
    f << "    if (state->events == nullptr) {\n        return nullptr;\n    }\n\n";
    f << "    Tox_Event_" << event_name << " *" << event_name_l << " = tox_events_add_" << event_name_l << "(state->events, state->mem);\n\n";
    f << "    if (" << event_name_l << " == nullptr) {\n";
    f << "        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;\n        return nullptr;\n    }\n\n";
    f << "    return " << event_name_l << ";\n}\n";


    f << R"(
/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

)";
    f << "void tox_events_handle_" << event_name_l << "(\n";
    f << "    Tox *tox";

    for (const auto& t : event_types) {
        std::visit(
            overloaded{
                [&](const EventTypeTrivial& t) {
                    f << ", " << t.type << " " << t.name;
                },
                [&](const EventTypeByteRange& t) {
                    f << ", const uint8_t *" << t.name_data << ", size_t " << t.name_length_cb;
                }
            },
            t
        );
    }

    f << ",\n    void *user_data)\n{\n";
    f << "    Tox_Event_" << event_name << " *" << event_name_l << " = tox_event_" << event_name_l << "_alloc(user_data);\n\n";
    f << "    if (" << event_name_l << " == nullptr) {\n        return;\n    }\n\n";

    for (const auto& t : event_types) {
        std::visit(
            overloaded{
                [&](const EventTypeTrivial& t) {
                    f << "    tox_event_" << event_name_l << "_set_" << t.name << "(" << event_name_l << ", " << t.name << ");\n";
                },
                [&](const EventTypeByteRange& t) {
                    f << "    tox_event_" << event_name_l << "_set_" << t.name_data << "(" << event_name_l << ", " << t.name_data << ", " << t.name_length_cb << ");\n";
                }
            },
            t
        );
    }
    f << "}\n";
}

// c++ generate_event_c.cpp -std=c++17 && ./a.out Friend_Lossy_Packet && diff --color ../../toxcore/events/friend_lossy_packet.c out/friend_lossy_packet.c
int main(int argc, char** argv) {
    // TODO: json?
    std::map<std::string, std::vector<EventType>> event_defs {
        {
            "Conference_Connected",
            {
                EventTypeTrivial{"uint32_t", "conference_number"},
            }
        },
        {
            "Conference_Invite",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeTrivial{"Tox_Conference_Type", "type"},
                EventTypeByteRange{"cookie", "cookie_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Conference_Message",
            {
                EventTypeTrivial{"uint32_t", "conference_number"},
                EventTypeTrivial{"uint32_t", "peer_number"},
                EventTypeTrivial{"Tox_Message_Type", "type"},
                EventTypeByteRange{"message", "message_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Conference_Peer_List_Changed",
            {
                EventTypeTrivial{"uint32_t", "conference_number"},
            }
        },
        {
            "Conference_Peer_Name",
            {
                EventTypeTrivial{"uint32_t", "conference_number"},
                EventTypeTrivial{"uint32_t", "peer_number"},
                EventTypeByteRange{"name", "name_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Conference_Title",
            {
                EventTypeTrivial{"uint32_t", "conference_number"},
                EventTypeTrivial{"uint32_t", "peer_number"},
                EventTypeByteRange{"title", "title_length", "length"}, // the latter two are ideally the same
            }
        },

        {
            "File_Chunk_Request",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeTrivial{"uint32_t", "file_number"},
                EventTypeTrivial{"uint64_t", "position"},
                EventTypeTrivial{"uint16_t", "length"},
            }
        },
        {
            "File_Recv",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeTrivial{"uint32_t", "file_number"},
                EventTypeTrivial{"uint32_t", "kind"},
                EventTypeTrivial{"uint64_t", "file_size"},
                EventTypeByteRange{"filename", "filename_length", "filename_length"},
            }
        },
        {
            "File_Recv_Chunk",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeTrivial{"uint32_t", "file_number"},
                EventTypeTrivial{"uint64_t", "position"},
                EventTypeByteRange{"data", "data_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "File_Recv_Control",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeTrivial{"uint32_t", "file_number"},
                EventTypeTrivial{"Tox_File_Control", "control"},
            }
        },

        {
            "Friend_Connection_Status",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeTrivial{"Tox_Connection", "connection_status"},
            }
        },
        {
            "Friend_Lossless_Packet",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeByteRange{"data", "data_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Friend_Lossy_Packet",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeByteRange{"data", "data_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Friend_Message",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeTrivial{"Tox_Message_Type", "type"},
                EventTypeByteRange{"message", "message_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Friend_Name",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeByteRange{"name", "name_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Friend_Read_Receipt",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeTrivial{"uint32_t", "message_id"},
            }
        },
#if 0
        {
            "Friend_Request",
            {
                //EventTypeTrivial{"uint32_t", "friend_number"}, // public_key ByteArray
                EventTypeByteRange{"message", "message_length", "length"}, // the latter two are ideally the same
            }
        },
#endif
        {
            "Friend_Status",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeTrivial{"Tox_User_Status", "status"},
            }
        },
        {
            "Friend_Status_Message",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeByteRange{"message", "message_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Friend_Typing",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeTrivial{"bool", "typing"},
            }
        },

        {
            "Self_Connection_Status",
            {
                EventTypeTrivial{"Tox_Connection", "connection_status"},
            }
        },

        {
            "Group_Peer_Name",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"uint32_t", "peer_id"},
                EventTypeByteRange{"name", "name_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Group_Peer_Status",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"uint32_t", "peer_id"},
                EventTypeTrivial{"Tox_User_Status", "status"},
            }
        },
        {
            "Group_Topic",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"uint32_t", "peer_id"},
                EventTypeByteRange{"topic", "topic_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Group_Privacy_State",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"Tox_Group_Privacy_State", "privacy_state"},
            }
        },
        {
            "Group_Voice_State",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"Tox_Group_Voice_State", "voice_state"},
            }
        },
        {
            "Group_Topic_Lock",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"Tox_Group_Topic_Lock", "topic_lock"},
            }
        },
        {
            "Group_Peer_Limit",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"uint32_t", "peer_limit"},
            }
        },
        {
            "Group_Password",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeByteRange{"password", "password_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Group_Message",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"uint32_t", "peer_id"},
                EventTypeTrivial{"Tox_Message_Type", "type"},
                EventTypeByteRange{"message", "message_length", "length"}, // the latter two are ideally the same
                EventTypeTrivial{"uint32_t", "message_id"},
            }
        },
        {
            "Group_Private_Message",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"uint32_t", "peer_id"},
                EventTypeTrivial{"Tox_Message_Type", "type"},
                EventTypeByteRange{"message", "message_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Group_Custom_Packet",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"uint32_t", "peer_id"},
                EventTypeByteRange{"data", "data_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Group_Custom_Private_Packet",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"uint32_t", "peer_id"},
                EventTypeByteRange{"data", "data_length", "length"}, // the latter two are ideally the same
            }
        },
        {
            "Group_Invite",
            {
                EventTypeTrivial{"uint32_t", "friend_number"},
                EventTypeByteRange{"invite_data", "invite_data_length", "length"}, // the latter two are ideally the same
                EventTypeByteRange{"group_name", "group_name_length", "group_name_length"}, // they are :)
            }
        },
        {
            "Group_Peer_Join",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"uint32_t", "peer_id"},
            }
        },
        {
            "Group_Peer_Exit",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"uint32_t", "peer_id"},
                EventTypeTrivial{"Tox_Group_Exit_Type", "exit_type"},
                EventTypeByteRange{"name", "name_length", "name_length"}, // they are :)
                EventTypeByteRange{"part_message", "part_message_length", "part_message_length"}, // they are :)
            }
        },
        {
            "Group_Self_Join",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
            }
        },
        {
            "Group_Join_Fail",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"Tox_Group_Join_Fail", "fail_type"},
            }
        },
        {
            "Group_Moderation",
            {
                EventTypeTrivial{"uint32_t", "group_number"},
                EventTypeTrivial{"uint32_t", "source_peer_id"},
                EventTypeTrivial{"uint32_t", "target_peer_id"},
                EventTypeTrivial{"Tox_Group_Mod_Event", "mod_type"},
            }
        },
    };

    if (argc < 2) {
        for (const auto& [event, event_types] : event_defs) {
            generate_event_impl(event, event_types);
        }
    } else {
        if (event_defs.count(argv[1])) {
            generate_event_impl(argv[1], event_defs[argv[1]]);
        } else {
            std::cerr << "error: unknown event " << argv[1] << "\n";
            return 1;
        }
    }

    return 0;
}

