#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>

#include <wsutil/wmem/wmem.h> 
#include <wsutil/time_util.h>
#include <wsutil/str_util.h>

#include "packet-4sight.h"

#define FRAME_HEADER_LEN 32

//FourSight Protocol constants
uint32_t _4SIGHT_HEADER_SIZE = 24;
uint32_t _4SIGHT_MAGIC_SIZE = 4;
uint32_t _4SIGHT_MESSAGE_TYPE_SIZE = 4;
uint32_t _4SIGHT_PAYLOAD_LENGTH_SIZE = 4;
uint32_t _4SIGHT_PROCESOR_ID_SIZE = 12;

const uint32_t _4SIGHT_TCP_PORT_1 = 64000;
const uint32_t _4SIGHT_TCP_PORT_2 = 64010;

uint32_t _4sight_offset_magic = 0;
uint32_t _4sight_offset_message_type = 4;
uint32_t _4sight_offset_payload_length = 8;
uint32_t _4sight_offset_processor_id = 12;

/* global handle for calling xml decoder if required */
static dissector_handle_t xml_handle;
static dissector_handle_t _4sight_handle = NULL;

static const value_string vs_message_types[] = {
        {0,  "Startup request"},
        {1,  "Update message"},
        {2,  "Startup end"},
        {3,  "Heartbeat"}
};

int dissect_4sight(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data);
int dissect_4sight_message(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data);

static heur_dissector_list_t heur_subdissector_list;

static int proto_4sight = -1;

static int ett_4sight_proto = -1;

static int hf_4sight_message_length = -1;
static int hf_4sight_message_type = -1;
static int hf_4sight_processor_id = -1;

static hf_register_info hf_4sight[] = {
        {&hf_4sight_message_length, {"Length",          "4sight.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_4sight_processor_id, {"Processor ID",          "4sight.processor_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_4sight_message_type,         {"Message type",       "4sight.message_type",               FT_UINT32,         BASE_DEC,          VALS(vs_message_types), 0x0, NULL, HFILL}}
};

static int* ett_4sight[] = {
        &ett_4sight_proto,
};

static bool _4sight_heur = true;

static heur_dtbl_entry_t* dissect_4sight_heur_tcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) {
    heur_dtbl_entry_t* res = NULL;

    static guint32 MAGIC = 0x80808080;

    if (tvb_captured_length(tvb) < 4) {
        return NULL;
    }

    guint32 magicBytes = tvb_get_uint32(tvb, _4sight_offset_magic, ENC_LITTLE_ENDIAN);

    if (magicBytes == MAGIC)
    {
        dissect_4sight(tvb, pinfo, tree, data);
        res = (heur_dtbl_entry_t*)1;
    }

    return res;
}

static guint32 get_4sight_message_len(packet_info* pinfo _U_, tvbuff_t* tvb, int offset _U_, void* data _U_)
{
    guint32 _4sight_message_length = tvb_get_uint32(tvb, _4sight_offset_payload_length, ENC_BIG_ENDIAN);
    return _4SIGHT_HEADER_SIZE + _4sight_message_length;
}

static guint32 get_4sight_payload_len(packet_info* pinfo _U_, tvbuff_t* tvb, int offset _U_, void* data _U_)
{
    guint32 _4sight_message_length = tvb_get_uint32(tvb, _4sight_offset_payload_length, ENC_BIG_ENDIAN);
    return _4sight_message_length;
}

int dissect_4sight(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) {

    tcp_dissect_pdus(tvb,
        pinfo,
        tree,
        TRUE,
        FRAME_HEADER_LEN,
        get_4sight_message_len, dissect_4sight_message, data);
    return tvb_reported_length(tvb);
}


int dissect_4sight_message(tvbuff_t* tvb _U_, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    int offset = 0;

    proto_item* ti = proto_tree_add_item(tree, proto_4sight, tvb, 0, -1, ENC_NA);
    proto_tree* _4sight_tree = proto_item_add_subtree(ti, ett_4sight_proto);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FourSight");

    //Magic (Offset 0)
    offset += 4;

    //Message type (Offset 4)
    guint32 messageType = tvb_get_uint32(tvb, _4sight_offset_message_type, ENC_BIG_ENDIAN);
    proto_tree_add_uint(_4sight_tree, hf_4sight_message_type, tvb, _4sight_offset_message_type, _4SIGHT_MESSAGE_TYPE_SIZE, messageType);
    offset += 4;

    //Payload length (Offset 8)
    guint32 packet_length = tvb_get_uint32(tvb, _4sight_offset_payload_length, ENC_BIG_ENDIAN);
    proto_tree_add_uint(_4sight_tree, hf_4sight_message_length, tvb, _4sight_offset_payload_length, _4SIGHT_PAYLOAD_LENGTH_SIZE, packet_length);
    offset += 4;

    //Processor id (Offset 12)
    guint8* processor_id = tvb_get_string_enc(pinfo->pool, tvb, _4sight_offset_processor_id, _4SIGHT_PROCESOR_ID_SIZE, ENC_UTF_8);

    proto_tree_add_string(_4sight_tree, hf_4sight_processor_id, tvb, _4sight_offset_processor_id, _4SIGHT_PROCESOR_ID_SIZE, (const char*)processor_id);
    offset += 12;

    //After header, dissect payload
    tvbuff_t* data_tvb = tvb_new_subset_remaining(tvb, _4SIGHT_HEADER_SIZE);
    add_new_data_source(pinfo, data_tvb, "Foursight Payload");
    if (xml_handle != NULL && packet_length > 0)
    {
        call_dissector(xml_handle, data_tvb, pinfo, tree);
    }

    return 0;
}

void proto_register_4sightproto(void) {
    module_t* _4sight_module;

    proto_4sight = proto_register_protocol("FourSight protocol", "FourSight", "foursight");
    _4sight_handle = register_dissector("foursight", dissect_4sight, proto_4sight);
    proto_register_field_array(proto_4sight, hf_4sight, array_length(hf_4sight));
    proto_register_subtree_array(ett_4sight, array_length(ett_4sight));

    _4sight_module = prefs_register_protocol(proto_4sight, NULL);
    heur_subdissector_list = register_heur_dissector_list("foursight", proto_4sight);
    prefs_register_bool_preference(_4sight_module, "heur",
        "Use heuristics for calculate if a TCP message is FourSight Protocol",
        "Use heuristics for calculate if a TCP message is FourSight Protocol",
        &_4sight_heur
    );
}

void proto_reg_handoff_4sightproto(void) {
    xml_handle = find_dissector_add_dependency("xml", proto_4sight);
    _4sight_handle = create_dissector_handle(dissect_4sight, proto_4sight);

    heur_dissector_t heuristic_dissector_function = (heur_dissector_t) dissect_4sight_heur_tcp;
    heur_dissector_add("tcp", heuristic_dissector_function, "FourSight over TCP", "foursight_tcp", proto_4sight, HEURISTIC_ENABLE);

    dissector_add_for_decode_as_with_preference("tcp.port", _4sight_handle);
}
