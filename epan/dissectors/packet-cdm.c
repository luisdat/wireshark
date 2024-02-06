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

#include "packet-cdm.h"
#include "packet-tcp.h"

#define FRAME_HEADER_LEN 32

//CDM Protocol constants
const uint32_t CDM_HEADER_SIZE = 47;
const uint32_t CDM_SOURCE_LENGTH = 5;
const uint32_t CDM_DESTINATION_LENGTH = 5;
const uint32_t CDM_MESSAGE_TYPE_LENGTH = 5;
const uint32_t CDM_SEQUENCE_NUMBER_LENGTH = 8;
const uint32_t CDM_MESSAGE_LENGTH_LENGTH = 9;
const uint32_t CDM_TIMESTAMP_LENGTH = 15;

const uint32_t CDM_TCP_PORT_1 = 30105;
const uint32_t CDM_TCP_PORT_2 = 30103;

const uint32_t offset_source = 0;
uint32_t offset_destination = 5; //offset_source + CDM_SOURCE_LENGTH;
uint32_t offset_message_type = 10; //offset_destination + CDM_DESTINATION_LENGTH;
uint32_t offset_sequence_number = 15; //offset_message_type + CDM_MESSAGE_TYPE_LENGTH;
uint32_t offset_message_length = 23; //offset_sequence_number + CDM_SEQUENCE_NUMBER_LENGTH;
uint32_t offset_timestamp = 32; //offset_message_length + CDM_MESSAGE_LENGTH_LENGTH;
	
/* global handle for calling xml decoder if required */
static dissector_handle_t xml_handle;

static guint8 * cdm_time_to_human(guint8* cdmTime) {
  static guint8 last_time[256];
  guint8* millis[4]; 
  memcpy(millis, &(cdmTime[12]), 3);
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

static nstime_t cdm_time_to_ws(guint8* cdmTime) {
  static nstime_t last_time;
  guint8* millis[4]; 
  memcpy(millis, &(cdmTime[12]), 3);
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

/*
struct CDMHeaderType
{
  char[5] source;
  char[5] destination;
  char[5] messageType;
  char[8] sequenceNumber;
  char[9] messageLength;
  char[15] timestamp;
};
*/

static const value_string vs_source[] = {
	{0,  "CDM"},
	{1,  "SACTA"},
	{2,  "ERROR"}
};

static const value_string vs_message_type[] = {
	{0,  "TEST"},
	{1,  "ACK"},
	{2,  "INFO"},
	{3,  "CARGA"},
	{4,  "ERROR"}
};

//void proto_register_cdmproto(void);
//void proto_reg_handoff_cdmproto(void);
int dissect_cdm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);
int dissect_cdm_message(tvbuff_t *tvb, packet_info * pinfo, proto_tree * tree, void * data);
static guint get_cdm_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_);
const char * get_cdm_message_length(uint16_t w_size);

static heur_dissector_list_t heur_subdissector_list;

static int proto_cdm = -1;

static int ett_cdm_proto = -1;
static int ett_cdm_src = -1;
static int ett_cdm_dst = -1;

static int hf_cdm_source = -1;
static int hf_cdm_destination = -1;
static int hf_cdm_message_type = -1;
static int hf_cdm_sequence_number = -1;
static int hf_cdm_message_length = -1;
static int hf_cdm_data_length = -1;
static int hf_cdm_timestamp = -1;

static hf_register_info hf_cdm[] = {
	{&hf_cdm_source,         {"Source",          "cdm.source", FT_UINT16, BASE_DEC, VALS(vs_source), 0x0, NULL, HFILL}},
	{&hf_cdm_destination,    {"Destination",     "cdm.destination",  FT_UINT16, BASE_DEC, VALS(vs_source), 0x0, NULL, HFILL}},
	{&hf_cdm_message_type  , {"Message type",    "cdm.message_type", FT_UINT16, BASE_DEC, VALS(vs_message_type), 0x0, NULL, HFILL}},
	{&hf_cdm_sequence_number,{"Sequence number", "cdm.sequence_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
	{&hf_cdm_message_length, {"Length",          "cdm.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
	{&hf_cdm_data_length,    {"Data length",     "cdm.data_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
	{&hf_cdm_timestamp,      {"Timestamp",       "cdm.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL}}
};

static int * ett_cdm[] = {
	&ett_cdm_proto,
	&ett_cdm_src,
	&ett_cdm_dst
};

static gboolean cdm_heur = true;

static bool dissect_cdm_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data) {
  bool res = false;

  static guint8 MAGIC1[] = "SACTA";
  static guint8 MAGIC2[] = "CDM  ";
	//uint16_t w_size = tvb_get_ntohs(tvb, 14);
	//unsigned int end_data = tvb_captured_length(tvb) - SACTA_HEADER_SIZE;
	guint8* cdm_source = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_source, CDM_SOURCE_LENGTH, ENC_UTF_8);
  if(memcmp(cdm_source, MAGIC1, 5) == 0 ||
     memcmp(cdm_source, MAGIC2, 5) == 0)
  {
    dissect_cdm(tvb, pinfo, tree, data);
	  res = true;
  }
	
	return res;
}

static guint get_cdm_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
  guint8* cdm_message_length = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_message_length, CDM_MESSAGE_LENGTH_LENGTH, ENC_UTF_8);
  int cdmLength = atoi(cdm_message_length);
  return cdmLength;
}

static guint16 get_source(guint8 *cdm_source)
{
  guint res = 2;
  if(strncmp(cdm_source, "CDM  ", 5) == 0)
  {
    res = 0;
  }
  else if(strncmp(cdm_source, "SACTA", 5) == 0)
  {
    res = 1;
  }

  return res;
}

static guint16 get_destination(guint8 *cdm_destination)
{
  guint res = 2;
  if(strncmp(cdm_destination, "CDM  ", 5) == 0)
  {
    res = 0;
  }
  else if(strncmp(cdm_destination, "SACTA", 5) == 0)
  {
    res = 1;
  }

  return res;
}

static guint16 get_message_type(guint8 *message_type)
{
  guint res = 4;
  if(strncmp(message_type, "TEST ", 5) == 0)
  {
    res = 0;
  }
  else if(strncmp(message_type, "ACK  ", 5) == 0)
  {
    res = 1;
  }
  else if(strncmp(message_type, "INFO ", 5) == 0)
  {
    res = 2;
  }
  else if(strncmp(message_type, "CARGA", 5) == 0)
  {
    res = 3;
  }

  return res;
}

int dissect_cdm(tvbuff_t *tvb, packet_info * pinfo, proto_tree * tree, void * data) {

  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                   get_cdm_message_len, dissect_cdm_message, data);
  return tvb_captured_length(tvb);
}


int dissect_cdm_message(tvbuff_t *tvb, packet_info * pinfo, proto_tree * tree, void * data _U_) {
	proto_item * ti = proto_tree_add_item(tree, proto_cdm, tvb, 0, -1, ENC_NA);
	proto_tree * cdm_tree = proto_item_add_subtree(ti, ett_cdm_proto);
	
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CDM");
	
        guint8* cdm_source = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_source, CDM_SOURCE_LENGTH, ENC_UTF_8);
	proto_tree_add_uint(cdm_tree, hf_cdm_source, tvb, offset_source, (gint16) strlen(cdm_source), get_source(cdm_source));

        guint8* cdm_destination = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_destination, CDM_DESTINATION_LENGTH, ENC_UTF_8);
	proto_tree_add_uint(cdm_tree, hf_cdm_destination, tvb, offset_destination, (gint16) strlen(cdm_destination), get_destination(cdm_destination));

	guint8* cdm_message_type = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_message_type, CDM_MESSAGE_TYPE_LENGTH, ENC_UTF_8);
	proto_tree_add_uint(cdm_tree, hf_cdm_message_type, tvb, offset_message_type, (gint16) strlen(cdm_message_type), get_message_type(cdm_message_type));

	guint8* cdm_sequence_number = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_sequence_number, CDM_SEQUENCE_NUMBER_LENGTH, ENC_UTF_8);
        guint32 cdm_sequence_number_int = atoi(cdm_sequence_number);
	proto_tree_add_uint(cdm_tree, hf_cdm_sequence_number, tvb, offset_sequence_number, (gint16) strlen(cdm_sequence_number), cdm_sequence_number_int);

	guint8* cdm_message_length = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_message_length, CDM_MESSAGE_LENGTH_LENGTH, ENC_UTF_8);
        guint32 cdm_message_length_int = atoi(cdm_message_length);
        guint32 cdm_data_length_int = cdm_message_length_int - CDM_HEADER_SIZE;
	proto_tree_add_uint(cdm_tree, hf_cdm_message_length, tvb, offset_message_length, (gint16) strlen(cdm_message_length), cdm_message_length_int);
        if(cdm_data_length_int > 0)
	{
	  proto_tree_add_uint(cdm_tree, hf_cdm_data_length, tvb, offset_message_length, (gint16) strlen(cdm_message_length), cdm_data_length_int);
	}

	guint8* cdm_timestamp = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_timestamp, CDM_TIMESTAMP_LENGTH, ENC_UTF_8);
        //guint8* cdm_time_readable = cdm_time_to_human(cdm_timestamp);
        nstime_t cdm_time = cdm_time_to_ws(cdm_timestamp);
	proto_tree_add_time(cdm_tree, hf_cdm_timestamp, tvb, offset_timestamp, CDM_TIMESTAMP_LENGTH, &cdm_time);

  guint packet_length = atoi(cdm_message_length);

  col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", "CDM", cdm_message_type);
  if(cdm_data_length_int > 0)
  {
    proto_item_append_text(ti, ", Message type: %s, Data length: %d",
                    cdm_message_type,
                    cdm_data_length_int);
  }
  else
  {
    proto_item_append_text(ti, ", Message type: %s, No data",
                    cdm_message_type);
  }
 
  //After header, dissect payload
	//heur_dtbl_entry_t * hdtbl_entry = NULL;
	tvbuff_t * data_tvb = tvb_new_subset_remaining(tvb, CDM_HEADER_SIZE);
	if (xml_handle != NULL && packet_length > CDM_HEADER_SIZE)
  {
		call_dissector(xml_handle, data_tvb, pinfo, tree);
  }

	return 0;
}

void proto_register_cdmproto(void) {
	module_t * cdm_module;
	
	proto_cdm = proto_register_protocol("CDM Protocol", "CDM", "cdm");
	proto_register_field_array(proto_cdm, hf_cdm, array_length(hf_cdm));
	proto_register_subtree_array(ett_cdm, array_length(ett_cdm));
	
	cdm_module = prefs_register_protocol(proto_cdm, NULL);
	heur_subdissector_list = register_heur_dissector_list("cdm", proto_cdm);
	prefs_register_bool_preference(cdm_module, "heur",
		"Use heuristics for calculate if a TCP message is CDM Protocol",
		"Use heuristics for calculate if a TCP message is CDM Protocol",
		&cdm_heur
	);
}

void proto_reg_handoff_cdmproto(void) {
	dissector_handle_t cdm_handle _U_;
	xml_handle = find_dissector_add_dependency("xml", proto_cdm);
	cdm_handle = create_dissector_handle(dissect_cdm, proto_cdm);
	//dissector_add_uint_with_preference("tcp.port1", CDM_TCP_PORT_1, cdm_handle);
	//dissector_add_uint_with_preference("tcp.port2", CDM_TCP_PORT_2, cdm_handle);
	heur_dissector_add("tcp", (heur_dissector_t) dissect_cdm_heur_tcp, "CDM over TCP", "cdm_tcp", proto_cdm, HEURISTIC_ENABLE);
}
