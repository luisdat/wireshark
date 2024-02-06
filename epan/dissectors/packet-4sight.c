#include "config.h"
/*
#include <time.h>
#include <iomanip>
#include <sstream>

extern "C" char* strptime(const char* s,
    const char* f,
    struct tm* tm) {
    // Isn't the C++ standard lib nice? std::get_time is defined such that its
    // format parameters are the exact same as strptime. Of course, we have to
    // create a string stream first, and imbue it with the current C locale, and
    // we also have to make sure we return the right things if it fails, or
    // if it succeeds, but this is still far simpler an implementation than any
    // of the versions in any of the C standard libraries.
    std::istringstream input(s);
    input.imbue(std::locale(setlocale(LC_ALL, nullptr)));
    input >> std::get_time(tm, f);
    if (input.fail()) {
        return nullptr;
    }
    return (char*)(s + input.tellg());
}
*/
/*
 * Just make sure we include the prototype for strptime as well
 * (needed for glibc 2.2) but make sure we do this only if not
 * yet defined.
 */
#ifndef __USE_XOPEN
#  define __USE_XOPEN
#endif
#ifndef _XOPEN_SOURCE
#  ifndef __sun
#    define _XOPEN_SOURCE 600
#  endif
#endif

/*
 * Defining _XOPEN_SOURCE is needed on some platforms, e.g. platforms
 * using glibc, to expand the set of things system header files define.
 *
 * Unfortunately, on other platforms, such as some versions of Solaris
 * (including Solaris 10), it *reduces* that set as well, causing
 * strptime() not to be declared, presumably because the version of the
 * X/Open spec that _XOPEN_SOURCE implies doesn't include strptime() and
 * blah blah blah namespace pollution blah blah blah.
 *
 * So we define __EXTENSIONS__ so that "strptime()" is declared.
 */
#ifndef __EXTENSIONS__
#  define __EXTENSIONS__
#endif

#ifndef HAVE_STRPTIME
# include "wsutil/ws_strptime.h"
#endif

#include "packet-4sight.h"
#include "packet-tcp.h"

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
uint32_t _4sight_offset_message_type = 4; //_4sight_offset_magic + _4SIGHT_MAGIC_SIZE; 
uint32_t _4sight_offset_payload_length = 8; //_4sight_offset_sequence + _4SIGHT_SEQUENCE_NUMBER_SIZE; 
uint32_t _4sight_offset_processor_id = 12; //_4sight_offset_sequence + _4SIGHT_SEQUENCE_NUMBER_SIZE; 
	
/* global handle for calling xml decoder if required */
static dissector_handle_t xml_handle;
static dissector_handle_t _4sight_handle = NULL;

static guint8 * _4sight_time_to_human(guint8* _4sightTime) {
  static guint8 last_time[256];
  guint8* millis[4]; 
  memcpy(millis, &(_4sightTime[12]), 3);
  millis[3] = '\0';
  /*
  struct tm myTM;
  if(strptime(cdmTime, "%d%m%y%H%M%S", &myTM))
  {
    gint milliseconds = atoi((const char*) millis);
	//const time_t epoch_time = (time_t)(seconds);
	//struct tm * utc = gmtime(&epoch_time);
	
	//int millis = microseconds / 1000;
	
	snprintf(last_time, sizeof(last_time), "%04d/%02d/%02d - %02d:%02d:%02d.%03d",
			myTM.tm_year + 1900,
			myTM.tm_mon + 1,
			myTM.tm_mday,
			myTM.tm_hour,
			myTM.tm_min,
			myTM.tm_sec,
		  milliseconds	
	);
  }
*/	
	return last_time;
}

static const value_string vs_message_types[] = {
        {0,  "Startup request"},
        {1,  "Update message"},
        {2,  "Startup end"},
        {3,  "Heartbeat"}
};

static nstime_t _4sight_time_to_ws(guint8* _4sightTime) {
  static nstime_t last_time;
  guint8* millis[4]; 
  memcpy(millis, &(_4sightTime[12]), 3);
  millis[3] = '\0';
  /*
  struct tm myTM;
  if(strptime(cdmTime, "%d%m%y%H%M%S", &myTM))
  {
    gint milliseconds = atoi((const char*) millis);
    last_time.secs = mktime(&myTM);
    last_time.nsecs = milliseconds * 1000000;
  }*/
	
  return last_time;
}

int dissect_4sight(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);
int dissect_4sight_message(tvbuff_t *tvb, packet_info * pinfo, proto_tree * tree, void * data);
static guint get_4sight_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_);

static heur_dissector_list_t heur_subdissector_list;

static int proto_4sight = -1;

static int ett_4sight_proto = -1;

static int hf_4sight_message_length = -1;
//static int hf_4sight_message_magic_number = -1;
static int hf_4sight_message_type = -1;
static int hf_4sight_processor_id = -1;

static hf_register_info hf_4sight[] = {
        {&hf_4sight_message_length, {"Length",          "4sight.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        //{&hf_4sight_message_magic_number, {"Magic number",          "4sight.magic_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
//        {&hf_4sight_message_type, {"Message type",          "4sight.message_type", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_4sight_processor_id, {"Processor ID",          "4sight.processor_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_4sight_message_type,         {"Message type",       "4sight.message_type",               FT_UINT32,         BASE_DEC,          VALS(vs_message_types), 0x0, NULL, HFILL}}
};

static int * ett_4sight[] = {
	&ett_4sight_proto,
};

static gboolean _4sight_heur = true;

static bool dissect_4sight_heur_tcp(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_) {
  bool res = false;

  //static guint8 MAGIC = 0x80;
  static guint32 MAGIC = 0x80808080;
  guint32 magicBytes = tvb_get_guint32(tvb, _4sight_offset_magic, ENC_LITTLE_ENDIAN);
  //guint8 magicByte = tvb_get_guint8(tvb, _4sight_offset_magic);

  if(magicBytes == MAGIC)
//  if(magicByte == MAGIC)
  {
    dissect_4sight(tvb, pinfo, tree, data);
	  res = true;
  }
	
  return res;
}

static guint32 get_4sight_message_len(packet_info* pinfo, tvbuff_t* tvb, int offset _U_, void* data _U_)
{
    guint32 _4sight_message_length = tvb_get_guint32(tvb, _4sight_offset_payload_length, ENC_BIG_ENDIAN);
    return _4SIGHT_HEADER_SIZE + _4sight_message_length;
}

static guint32 get_4sight_payload_len(packet_info* pinfo, tvbuff_t* tvb, int offset _U_, void* data _U_)
{
    guint32 _4sight_message_length = tvb_get_guint32(tvb, _4sight_offset_payload_length, ENC_BIG_ENDIAN);
    return _4sight_message_length;
}

int dissect_4sight(tvbuff_t *tvb, packet_info * pinfo, proto_tree * tree, void * data) {

  tcp_dissect_pdus(tvb,
                   pinfo,
                   tree,
                   TRUE,
                   FRAME_HEADER_LEN,
                   get_4sight_message_len, dissect_4sight_message, data);
  return tvb_reported_length(tvb);
  //return tvb_captured_length(tvb);
}


int dissect_4sight_message(tvbuff_t *tvb _U_, packet_info * pinfo, proto_tree * tree _U_, void * data _U_) {
    int offset = 0;
        /*
        proto_item* ti = proto_tree_add_item(tree, proto_4sight, tvb, 0, -1, ENC_NA);
        proto_tree* cdm_tree = proto_item_add_subtree(ti, ett_4sight_proto);
        proto_tree_add_uint(cdm_tree, hf_4sight_message_length, tvb, _4sight_offset_payload_length, 4, 123);
        */

	proto_item * ti = proto_tree_add_item(tree, proto_4sight, tvb, 0, -1, ENC_NA);
	proto_tree * _4sight_tree = proto_item_add_subtree(ti, ett_4sight_proto);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FourSight");

        //Magic
        //guint32 magicBytes = tvb_get_guint32(tvb, _4sight_offset_magic, ENC_LITTLE_ENDIAN);
        //proto_tree_add_uint(_4sight_tree, hf_4sight_message_magic_number, tvb, _4sight_offset_magic, _4SIGHT_MAGIC_SIZE, magicBytes);
        offset += 4;

        //Message type
        guint32 messageType = tvb_get_guint32(tvb, _4sight_offset_message_type, ENC_BIG_ENDIAN);
        proto_tree_add_uint(_4sight_tree, hf_4sight_message_type, tvb, _4sight_offset_message_type, _4SIGHT_MESSAGE_TYPE_SIZE, messageType);
        offset += 4;

        //Payload length
        guint packet_length = get_4sight_payload_len(pinfo, tvb, _4sight_offset_payload_length, data);
        proto_tree_add_uint(_4sight_tree, hf_4sight_message_length, tvb, _4sight_offset_payload_length, _4SIGHT_PAYLOAD_LENGTH_SIZE, packet_length);
        offset += 4;

        //Processor id
        guint8* processor_id = tvb_get_string_enc(wmem_packet_scope(), tvb, _4sight_offset_processor_id, _4SIGHT_PROCESOR_ID_SIZE, ENC_UTF_8);
        proto_tree_add_string(_4sight_tree, hf_4sight_processor_id, tvb, _4sight_offset_processor_id, _4SIGHT_PROCESOR_ID_SIZE, processor_id);
        offset += 12;

        //After header, dissect payload
	//heur_dtbl_entry_t * hdtbl_entry = NULL;
        tvbuff_t * data_tvb = tvb_new_subset_remaining(tvb, _4SIGHT_HEADER_SIZE);
        add_new_data_source(pinfo, data_tvb, "Foursight Payload");
        if (xml_handle != NULL && packet_length > 0)
        {
	  call_dissector(xml_handle, data_tvb, pinfo, tree);
        }

	return 0;
}

void proto_register_4sightproto(void) {
	module_t * _4sight_module;

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
	//dissector_handle_t _4sight_handle _U_;
	xml_handle = find_dissector_add_dependency("xml", proto_4sight);
	_4sight_handle = create_dissector_handle(dissect_4sight, proto_4sight);
	heur_dissector_add("tcp", (heur_dissector_t) dissect_4sight_heur_tcp, "FourSight over TCP", "foursight_tcp", proto_4sight, HEURISTIC_ENABLE);
        dissector_add_for_decode_as_with_preference("tcp.port", _4sight_handle);
}
