

/*
 * packet-sacta.c
 *
 *  Created on: 12 jun. 2019
 *      Author: gromerov
 */

#include "packet-sacta.h"
#include "address_types.h"
#include "wsutil/inet_addr.h"
#include "epan/expert.h"
#include <epan/reassemble.h>

 /* packet reassembly */
static reassembly_table msg_reassembly_table;
/* end packet reassebly */

#define PATH_SIZE  1024
#define SACTA_UDP_PORT  31161
#define SACTA_MESSAGE_TEXT_SIZE  64
#define CABX_TRUE 0x01
#define CABX_FALSE 0x00

static gboolean save_fragmented;

static int TAMANO_CABX = 128;
static int TAMANO_CABX_ARIS = 24;
static int TAMANO_CABX_eVerest = 2;
static int TAMANO_CABX_autonomo = 4;
static int TAMANO_ARIS_VERSION_ID = 2;
static int TAMANO_ARIS_ADAPTACION = 18;
static int TAMANO_ARIS_DEPENDENCIA = 4;

static array_string array_dominios;
static array_string array_centros;
static array_string array_usuarios;
static array_string array_tipos;

static heur_dissector_list_t heur_subdissector_list;

static int proto_sacta = -1;

static const uint16_t SACTA_HEADER_SIZE = 20;
static dissector_handle_t asterix_handle;
static dissector_handle_t xml_handle;

enum TiposInterceptor {
    TIPO_INTERCEPTOR_EVEREST = 0xBEBA,
    TIPO_INTERCEPTOR_ARIS = 0xCAFE,
    TIPO_INTERCEPTOR_AUTONOMO = 0xBBAA,
};

static const char* STR_TIPO_INTERCEPTOR_ARIS = "ARIS";
static const char* STR_TIPO_INTERCEPTOR_EVEREST = "eVerest";
static const char* STR_TIPO_INTERCEPTOR_AUTONOMO = "Autonomo";
static const char* STR_TIPO_INTERCEPTOR_DESCONOCIDO = "DESCONOCIDO";

static int OFFSET_ORIGEN_DOMINIO = 0;
static int OFFSET_ORIGEN_CENTRO = 1;
static int OFFSET_ORIGEN_USUARIO = 2;
static int OFFSET_DESTINO_DOMINIO = 4;
static int OFFSET_DESTINO_CENTRO = 5;
static int OFFSET_DESTINO_USUARIO = 6;
static int OFFSET_INSTANCIA = 8;
static int OFFSET_SESION = 9;
static int OFFSET_TIPO = 10;
static int OFFSET_OPCIONES_SECUENCIA = 12;
static int OFFSET_LONGITUD = 14;
static int OFFSET_HORA = 16;

static int FLAG_CABECERA_EXTENDIDA = 0x01;

static reassembly_table sacta_reassembly_table;

static int hf_sacta_src_dominio = -1;
static int hf_sacta_nspv_paquete = -1;
static int hf_sacta_nspv_paquete_len = -1;
static int hf_sacta_src_centro = -1;
static int hf_sacta_origen_cabx = -1;
static int hf_sacta_destino_cabx = -1;
static int hf_sacta_src_usuario = -1;
static int hf_sacta_dst_dominio = -1;
static int hf_sacta_dst_centro = -1;
static int hf_sacta_dst_usuario = -1;
static int hf_sacta_instancia = -1;
static int hf_sacta_sesion = -1;
static int hf_sacta_tipo = -1;
static int hf_sacta_tipoTexto = -1;
static int hf_sacta_longitud_udp = -1;
static int hf_sacta_opciones = -1;
static int hf_sacta_secuencia = -1;
static int hf_sacta_longitud = -1;
static int hf_sacta_longitud_bytes = -1;
static int hf_longitud_real = -1;
static int hf_cabeceras_extendidas = -1;
static int hf_longitud_descomprimida = -1;
static int hf_datos_comprimidos = -1;
static int hf_ratio_compresion = -1;
static int hf_sacta_fecha = -1;
static int hf_sacta_tipo_cabx = -1;
static int hf_sacta_sin_datos = -1;
static int hf_sacta_numero_cabx = -1;
static int hf_aris_version_id = -1;
static int hf_aris_adaptacion = -1;
static int hf_aris_dependencia = -1;
static int hf_cabx_tipo = -1;
static int hf_sacta_autonomo_mv = -1;
static int hf_sacta_autonomo_mt = -1;
static int hf_sacta_autonomo_ms = -1;
static int hf_sacta_autonomo_mm = -1;
static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;
static int hf_msg_reassembled_data = -1;

static int ett_sacta_proto = -1;
static int ett_sacta_datos = -1;
static int ett_sacta_cabx = -1;
static int ett_sacta_src = -1;
static int ett_sacta_dst = -1;
static int ett_cabx_aris = -1;
static int ett_cabx_eVerest = -1;
static int ett_cabx_autonomo = -1;
static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static int offset_sacta_nspv_paquete_len = 6;
static int offset_sacta_nspv_len = 8;
static int SACTA_NSPV_LEN = 8;

static expert_field ei_sacta_decompression_failed = EI_INIT;
/*
 * Set up expert info.
 */
static ei_register_info ei[] = {
    { &ei_sacta_decompression_failed,
      { "sacta.decompression.failed", PI_MALFORMED, PI_ERROR,
        "SACTA packet decompression failed",
        EXPFILL }
    }
};

static const value_string vs_opciones[] = {
        {0,  "com_msj_datos"},
        {1,  "com_msj_cabx"},
        {2,  "com_msj_presencia"},
        {3,  "unused"},
        {4,  "com_msj_inicio_seq"},
        {5,  "unused"},
        {6,  "com_msj_datos_encript"},
        {7,  "unused"},
        {8,  "com_msj_datos_comprim"},
        {9,  "unused"},
        {10, "com_msj_datos_comp_enc"},
        {12, "com_msj_datos_ftp"},
        {14, "com_msj_datos_rsh"}
};

static const fragment_items msg_frag_items = {
    /* Fragment subtrees */
    &ett_msg_fragment,
    &ett_msg_fragments,
    /* Fragment fields */
    &hf_msg_fragments,
    &hf_msg_fragment,
    &hf_msg_fragment_overlap,
    &hf_msg_fragment_overlap_conflicts,
    &hf_msg_fragment_multiple_tails,
    &hf_msg_fragment_too_long_fragment,
    &hf_msg_fragment_error,
    &hf_msg_fragment_count,
    /* Reassembled in field */
    &hf_msg_reassembled_in,
    /* Reassembled length field */
    &hf_msg_reassembled_length,
    &hf_msg_reassembled_data,
    /* Tag */
    "Message fragments"
};
static hf_register_info hf_sacta[] = {
  {&hf_sacta_nspv_paquete,     {"Paquete NSPV",   "sacta.nspv.paquete",           FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
  {&hf_sacta_src_dominio,      {"Dominio",        "sacta.src.dominio",            FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_src_centro,       {"Centro",         "sacta.src.centro",             FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_src_usuario,      {"Usuario",        "sacta.src.usuario",            FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_dst_dominio,      {"Dominio",        "sacta.dst.dominio",            FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_dst_centro,       {"Centro",         "sacta.dst.centro",             FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_dst_usuario,      {"Usuario",        "sacta.dst.usuario",            FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
  {&hf_sacta_instancia,        {"Instancia",      "sacta.instancia",              FT_UINT8,         BASE_DEC,          NULL,              0x0, NULL, HFILL}},
  {&hf_sacta_nspv_paquete_len, {"Longitud",       "sacta.nspv.longitud_paquete",  FT_UINT16,        BASE_DEC,          NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_sesion,           {"Sesion",         "sacta.sesion",                 FT_UINT8,         BASE_DEC,          NULL,              0x0, NULL, HFILL}},
  {&hf_sacta_tipo,             {"Tipo",           "sacta.tipo",                   FT_UINT16,        BASE_DEC,          NULL,              0x0, NULL, HFILL}},
  {&hf_sacta_longitud_udp,             {"Longitud UDP",           "sacta.longitud_udp",                   FT_UINT16,        BASE_DEC,          NULL,              0x0, NULL, HFILL}},
  {&hf_sacta_tipoTexto,        {"Tipo de mensaje",     "sacta.tipoTexto",             FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_opciones,         {"Opciones",       "sacta.opciones",               FT_UINT8,         BASE_HEX,          VALS(vs_opciones), 0x0, NULL, HFILL}},
        {&hf_sacta_secuencia,        {"Secuencia",      "sacta.secuencia",              FT_UINT16,        BASE_DEC,          NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_longitud,         {"Longitud datos",       "sacta.longitud",               FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_longitud_bytes,         {"Longitud en bytes",       "sacta.longitud_bytes",               FT_UINT16,        BASE_DEC,         NULL,              0x0, NULL, HFILL}},
        {&hf_datos_comprimidos,         {"Datos comprimidos",       "sacta.datos_comprimidos",               FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_ratio_compresion,         {"Ratio compresion",       "sacta.ratio",               FT_FLOAT,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_longitud_real,        {"Longitud de datos",      "sacta.longitud_real",              FT_UINT16,        BASE_DEC,          NULL,              0x0, NULL, HFILL}},
        {&hf_cabeceras_extendidas,        {"Cabeceras extendidas",      "sacta.cabeceras_extendidas",              FT_UINT16,        BASE_DEC,          NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_fecha,            {"Fecha",          "sacta.fecha",                  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,              0x0, NULL, HFILL}},
        {&hf_longitud_descomprimida,        {"Longitud descomprimida",      "sacta.longitud_descomprimida",              FT_UINT16,        BASE_DEC,          NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_tipo_cabx,        {"Cabecera extendida", "sacta.cabx",               FT_BOOLEAN,       BASE_DEC,         NULL,               0x0, NULL, HFILL}},
        {&hf_sacta_sin_datos,        {"Mensaje sin datos", "sacta.sin_datos",               FT_NONE,       BASE_NONE,         NULL,               0x0, NULL, HFILL}},
        {&hf_sacta_numero_cabx,      {"Numero de cabeceras extendidas", "sacta.num_cabx",               FT_UINT16,       BASE_DEC,         NULL,               0x0, NULL, HFILL}},
        {&hf_cabx_tipo,              {"Tipo",           "sacta.tipo_cabx",              FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_aris_version_id,        {"Version Id",     "sacta.aris.version_id",        FT_UINT16,        BASE_DEC,          NULL,              0x0, NULL, HFILL}},
        {&hf_aris_dependencia,       {"Dependencia",    "sacta.aris.dependencia",       FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_aris_adaptacion,        {"Adaptacion",     "sacta.aris.adaptacion",        FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_autonomo_mv,      {"Modo Vigilancia","sacta.autonomo.modoVigilancia",FT_BOOLEAN,       BASE_DEC,          NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_autonomo_mt,      {"Modo TLPV",      "sacta.autonomo.modoTPLV",      FT_BOOLEAN,       BASE_DEC,          NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_autonomo_ms,      {"Modo SMCT",      "sacta.autonomo.modoSMCT",      FT_BOOLEAN,       BASE_DEC,          NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_autonomo_mm,      {"Modo Manual",    "sacta.autonomo.modoManual",    FT_BOOLEAN,       BASE_DEC,          NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_origen_cabx,      {"Origen",         "sacta.eVerest.origen",         FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_sacta_destino_cabx,     {"Destino",        "sacta.eVerest.destino",        FT_STRING,        BASE_NONE,         NULL,              0x0, NULL, HFILL}},
        {&hf_msg_fragments, {"Message fragments", "sacta.fragments", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment, {"Message fragment", "sacta.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_overlap, {"Message fragment overlap", "sacta.fragment.overlap", FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_overlap_conflicts, {"Message fragment overlapping with conflicting data", "sacta.fragment.overlap.conflicts", FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_multiple_tails, {"Message has multiple tail fragments", "sacta.fragment.multiple_tails", FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } }, 
        {&hf_msg_fragment_too_long_fragment, {"Message fragment too long", "sacta.fragment.too_long_fragment", FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } }, 
        {&hf_msg_fragment_error, {"Message defragmentation error", "sacta.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_count, {"Message fragment count", "sacta.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_reassembled_in, {"Reassembled in", "sacta.reassembled.in", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_reassembled_length, {"Reassembled length", "sacta.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_reassembled_data, {"Reassembled data", "sacta.reassembled.data", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } }
};

static int* ett_sacta[] = {
        &ett_sacta_proto,
        &ett_sacta_datos,
        &ett_sacta_cabx,
        &ett_sacta_src,
        &ett_sacta_dst,
        &ett_cabx_aris,
        &ett_cabx_eVerest,
        &ett_cabx_autonomo,
        & ett_msg_fragment,
        & ett_msg_fragments
};

static int sacta_heur = true;

static char _sacta_message_text[SACTA_MESSAGE_TEXT_SIZE];

extern void address_to_str_buf(const address* addr, gchar* buf, int buf_len);
bool isLocalhost(struct _address* addr);
bool isLocalhost(struct _address* addr)
{
    static const char* Localhost = "127.0.0.1";
    gchar         addr_str[WS_INET6_ADDRSTRLEN];
    address_to_str_buf(addr, addr_str, sizeof(addr_str));
    return strcmp(addr_str, Localhost) == 0;
}


gint16
sacta_get_gint16(packet_info* pinfo, tvbuff_t* tvb, const gint offset) {
    gint16 w_size = 0;
    if (isLocalhost(&pinfo->net_dst)) {
        w_size = tvb_get_gint16(tvb, offset, ENC_LITTLE_ENDIAN);
    }
    else {
        w_size = tvb_get_gint16(tvb, offset, ENC_BIG_ENDIAN);
    }
    return w_size;
}

gint32
sacta_get_gint32(packet_info* pinfo, tvbuff_t* tvb, const gint offset) {
    gint32 w_size = 0;
    if (isLocalhost(&pinfo->net_dst)) {
        w_size = tvb_get_gint32(tvb, offset, ENC_LITTLE_ENDIAN);
    }
    else {
        w_size = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
    }
    return w_size;
}

static bool isXMLPacket(tvbuff_t* backing, const gint backing_offset, const gint backing_length, const gint reported_length)
{
    static gint C_XML_MAGIC_LENGTH = 5;
    static guint8 C_XML_MAGIC[] = "<?xml";
    bool res = false;
    if (backing_length >= C_XML_MAGIC_LENGTH &&
        reported_length >= C_XML_MAGIC_LENGTH)
    {
        guint8* starting_bytes = tvb_get_string_enc(wmem_packet_scope(), backing, backing_offset, C_XML_MAGIC_LENGTH, ENC_UTF_8);
        if (memcmp(starting_bytes, C_XML_MAGIC, C_XML_MAGIC_LENGTH) == 0)
        {
            res = true;
        }
    }

    return res;
}
int dissect_sacta(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data);
const char* get_sacta_message_length(uint16_t w_size);
const char* get_sacta_message_field(array_string* array, uint32_t index);

const char* get_sacta_message_length(uint16_t w_size) {
    snprintf(_sacta_message_text, SACTA_MESSAGE_TEXT_SIZE, "%u words (%u bytes)", w_size, 2 * w_size);
    return _sacta_message_text;
}

const char* get_sacta_message_field(array_string* array, uint32_t index) {
    const char* field_name = array_string_get(array, index);
    if (index == 0) {
        snprintf(_sacta_message_text, SACTA_MESSAGE_TEXT_SIZE, "HEARTBEAT");
    }
    else if (field_name != NULL) {
        snprintf(_sacta_message_text, SACTA_MESSAGE_TEXT_SIZE, "%s (%d)", field_name, index);
    }
    else {
        snprintf(_sacta_message_text, SACTA_MESSAGE_TEXT_SIZE, "Unknown (%d)", index);
    }
    return _sacta_message_text;
}

const char* get_sacta_info(array_string* array, uint32_t index) {
    const char* field_name = array_string_get(array, index);
    if (field_name != NULL) {
        snprintf(_sacta_message_text, SACTA_MESSAGE_TEXT_SIZE, "%s", field_name);
    }
    else {
        snprintf(_sacta_message_text, SACTA_MESSAGE_TEXT_SIZE, "Unknown (%d)", index);
    }
    return _sacta_message_text;
}

int reassemble_sacta_msg(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data);
int dissect_sacta_nspv(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree);

static gboolean is_sacta_fragmented(tvbuff_t* tvb, packet_info* pinfo) {
    gboolean res = false;
    unsigned int end_data = tvb_reported_length(tvb) - SACTA_HEADER_SIZE;
    //unsigned int end_data = tvb_captured_length(tvb) - SACTA_HEADER_SIZE;
    uint16_t w_size = sacta_get_gint16(pinfo, tvb, 14);
    struct tvbuff* top_tvb = tvb_get_ds_tvb(tvb);
    uint16_t longitud_udp = sacta_get_gint16(pinfo, top_tvb, 38);

    if (
        (end_data >= SACTA_HEADER_SIZE) &&
        (end_data == 2 * w_size + TAMANO_CABX ||
         end_data == 2 * w_size + 2 * TAMANO_CABX ||
         end_data == 2 * w_size + 3 * TAMANO_CABX))
    {
        res = false;
    }
    else if(longitud_udp > 2 * w_size)
    {
        res = true;
    }
    return res;
}

static int dissect_fragmented_sacta(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data);

static int dissect_sacta_heur_udp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) {
    int res = 0;
    // Minimo tendra cabecera SACTA, o no sera mensaje SACTA
    if (tvb_captured_length(tvb) >= SACTA_HEADER_SIZE) {
        // Mirar si es trafico de NSPV (java serializado)
        static guint8 MAGIC1[] = "es.indra.";
        guint8* sacta_nspv = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_sacta_nspv_len, SACTA_NSPV_LEN, ENC_UTF_8);
        if (memcmp(sacta_nspv, MAGIC1, 8) == 0)
        {
            dissect_sacta_nspv(tvb, pinfo, tree); //, data);
            res = 1;
        }
        else {

            uint16_t w_size = sacta_get_gint16(pinfo, tvb, 14);
            unsigned int end_data = tvb_captured_length(tvb) - SACTA_HEADER_SIZE;
            //Dominio > 7, instancia > 7, sesion > 7 => supone que no es cabecera SACTA
            uint8_t sacta_src_dominio = tvb_get_guint8(tvb, 0);
            uint8_t sacta_dst_dominio = tvb_get_guint8(tvb, 4);
            uint8_t sacta_instancia = tvb_get_guint8(tvb, 8);
            uint8_t sacta_sesion = tvb_get_guint8(tvb, 9);
            int dissect_sacta_ok = sacta_src_dominio <= 7 && sacta_dst_dominio <= 7 && sacta_instancia <= 7 && sacta_sesion <= 7;

            if (dissect_sacta_ok)
            {
                if (end_data == 2 * w_size) {
                    dissect_sacta(tvb, pinfo, tree, data);
                    res = 1;
                }
                else {
                    //Caso especial: con cabecera extendida pero sin flag
                    /*
                    if (
                        (end_data == 2 * w_size + TAMANO_CABX ||
                            end_data == 2 * w_size + 2 * TAMANO_CABX ||
                            end_data == 2 * w_size + 3 * TAMANO_CABX))
                    {
                        dissect_sacta(tvb, pinfo, tree, data);
                        res = 1;
                    }
                    else
                    {
                    */
                        // TODO: Agrupar todos los fragmentos
                        struct tvbuff* top_tvb = tvb_get_ds_tvb(tvb);
                        uint16_t longitud_udp = sacta_get_gint16(pinfo, top_tvb, 38);
                        uint16_t flag_more_fragments = sacta_get_gint16(pinfo, top_tvb, 20) & 0xE000;
                        gint16 fragment_offset = sacta_get_gint16(pinfo, top_tvb, 20) & 0x1FFF;
                        if ((flag_more_fragments || fragment_offset > 0) && longitud_udp > w_size)
                        {
                            dissect_fragmented_sacta(tvb, pinfo, tree, data); // != -1)
                        }
                    /* } */
                }
            }
        }
    }

    return res;
}

int dissect_sacta_nspv(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree) {
    proto_item* ti = proto_tree_add_item(tree, proto_sacta, tvb, 0, -1, ENC_NA);
    proto_tree* sacta_tree = proto_item_add_subtree(ti, ett_sacta_proto);
    gint16 tamano_paquete = tvb_get_gint16(tvb, offset_sacta_nspv_paquete_len, ENC_BIG_ENDIAN);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SACTA_NSPV");
    guint8* paquete_nspv = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_sacta_nspv_len, tamano_paquete, ENC_UTF_8);
    proto_tree_add_string(sacta_tree, hf_sacta_nspv_paquete, tvb, offset_sacta_nspv_len, tamano_paquete /*tamano_paquete*/, paquete_nspv);

    call_data_dissector(tvb, pinfo, sacta_tree);
    return 0;
}

bool existe_cabx(packet_info* pinfo, tvbuff_t* tvb)
{
    bool res = false;
    uint16_t sacta_sec_y_ops = sacta_get_gint16(pinfo, tvb, 12);
    uint16_t sacta_opciones = (sacta_sec_y_ops & 0x0F000) >> 12;
    res = (sacta_opciones & FLAG_CABECERA_EXTENDIDA) != 0;
    if (!res) {
        uint16_t w_size = sacta_get_gint16(pinfo, tvb, 14);
        unsigned int end_data = tvb_captured_length(tvb) - SACTA_HEADER_SIZE;
        if (
                (end_data == 2 * w_size + TAMANO_CABX ||
                    end_data == 2 * w_size + 2 * TAMANO_CABX ||
                    end_data == 2 * w_size + 3 * TAMANO_CABX))
        {
            res = true;
        }
    }
    return res;
}

uint16_t get_num_cabeceras_extendidas(packet_info* pinfo, tvbuff_t* tvb, uint16_t longitud_datos) {
    uint16_t res = 0;
    uint16_t siguiente_cabx = 0;
    uint32_t comienzo_cabx = longitud_datos - TAMANO_CABX;
    do {
        siguiente_cabx = sacta_get_gint16(pinfo, tvb, comienzo_cabx + 2);
        comienzo_cabx -= TAMANO_CABX;
        res++;
    } while (comienzo_cabx > 0 && siguiente_cabx != 0);
    return res;
}

void dissect_cabx(tvbuff_t* tvb, int offset, proto_tree* cabecera_tree) {
    /* proto_tree * cabecera_ext_tree =    */ proto_tree_add_subtree(cabecera_tree, tvb, offset, TAMANO_CABX, 0, NULL, "Cabecera SACTA");
}

int dissect_fragmented_sacta(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) {
    //Flag "more fragments"
    struct tvbuff* top_tvb = tvb_get_ds_tvb(tvb);
    //uint16_t msg_seqid = sacta_get_gint16(pinfo, top_tvb, 18);
    /*
    if (msg_seqid == 0)
    {
        return -1;
    }
    */
    //uint16_t id_msg = sacta_get_gint16(pinfo, top_tvb, 14);
    //uint16_t flags_msg = sacta_get_gint16(pinfo, top_tvb, 16);

    expert_module_t* expert_sacta = expert_register_protocol(proto_sacta);
    expert_register_field_array(expert_sacta, ei, array_length(ei));

    proto_item* ti = proto_tree_add_item(tree, proto_sacta, tvb, 0, -1, ENC_NA);
    proto_tree* sacta_tree = proto_item_add_subtree(ti, ett_sacta_proto);

    int offset = 0;
    gboolean more_fragments = FALSE;
    //guint8      flags;
    tvbuff_t* next_tvb = NULL;

    /*Assembly part */
    save_fragmented = pinfo->fragmented;
    //flags = tvb_get_guint8(top_tvb, 16);
    //offset++;
    gint16 fragmented = sacta_get_gint16(pinfo, top_tvb, 20) & 0xE000;
    gint16 fragment_offset = sacta_get_gint16(pinfo, top_tvb, 20) & 0x1FFF;
    if (fragmented || fragment_offset > 0) { // flags & save_fragmented) { /* fragmented */
        if (!fragmented && fragment_offset > 0)
        {
            more_fragments = FALSE;
        }
        tvbuff_t* new_tvb = NULL;
        fragment_head* frag_msg = NULL;
        //guint16 msg_seqid = tvb_get_ntohs(tvb, offset); offset += 2;
        uint16_t msg_seqid = sacta_get_gint16(pinfo, top_tvb, 18);
        //guint16 msg_num = tvb_get_ntohs(tvb, offset); offset += 2;
        //gint16 fragment_offset = sacta_get_gint16(pinfo, top_tvb, 20) & 0x1FFF;
        uint16_t msg_num = 1;
        proto_tree_add_uint(sacta_tree, hf_sacta_longitud_udp, top_tvb, 18, 2, msg_seqid);
        proto_tree_add_uint(sacta_tree, hf_sacta_longitud_udp, top_tvb, 20, 2, fragment_offset);
        proto_tree_add_uint(sacta_tree, hf_sacta_longitud_udp, top_tvb, 20, 2, fragmented);


        pinfo->fragmented = TRUE;
        /*
        frag_msg = fragment_add_seq_check(msg_reassembly_table,
            tvb, offset, pinfo,
            msg_seqid, NULL, /-* ID for fragments belonging together *-/
            msg_num, /-* fragment sequence number *-/
            tvb_captured_length_remaining(tvb, offset), /-* fragment length - to the end *-/
            flags & FL_FRAG_LAST); /-* More fragments? *-/
            */
        frag_msg = fragment_add_seq_next(&msg_reassembly_table,
            tvb, offset, pinfo,
            msg_seqid, NULL,                            /* ID for fragments belonging together */
            fragment_offset, //tvb_captured_length_remaining(tvb, msg_offset),
            more_fragments);
        new_tvb = process_reassembled_data(tvb, offset, pinfo,
            "Reassembled Message", frag_msg, &msg_frag_items,
            NULL, sacta_tree);

        if (frag_msg) { /* Reassembled */
            col_append_str(pinfo->cinfo, COL_INFO,
                " (Message Reassembled)");
        }
        else { /* Not last packet of reassembled Short Message */
            col_append_fstr(pinfo->cinfo, COL_INFO,
                " (Message fragment %u)", msg_num);
        }
        offset += fragment_offset;

        if (new_tvb) { /* take it all */
            next_tvb = new_tvb;
        }
        else { /* make a new subset */
            next_tvb = tvb_new_subset_remaining(tvb, fragment_offset);
        }
    }
    else { /* Not fragmented */
        next_tvb = tvb_new_subset_remaining(tvb, offset);
    }

    dissect_sacta(next_tvb, pinfo, tree, data);
    return offset;
}

int dissect_sacta(tvbuff_t * tvb, packet_info * pinfo, proto_tree* tree, void* data) {
    uint32_t offset = 0; //Se va sumando segun avanzamos cabecera, datos, extendidas ...
    const char* text = NULL;
    const char* tipo = NULL;

    //SACTA_tree en el caso de los fragmentados?

    proto_item* ti = proto_tree_add_item(tree, proto_sacta, tvb, 0, -1, ENC_NA);
    proto_tree* sacta_tree = proto_item_add_subtree(ti, ett_sacta_proto);
    struct tvbuff* top_tvb = tvb_get_ds_tvb(tvb);
    uint16_t longitud_udp = sacta_get_gint16(pinfo, top_tvb, 4);
    proto_tree_add_uint(sacta_tree, hf_sacta_longitud_udp, top_tvb, 4, 2, longitud_udp);


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SACTA_COM");

    //Obtencion de longitud
    guint longitud_real = tvb_reported_length(tvb);

    //Obtencion de longitud
    //uint16_t sacta_longitud = sacta_get_gint16(pinfo, tvb, OFFSET_LONGITUD) * 2;

    // Obtencion del origen
    uint8_t sacta_src_dominio = tvb_get_guint8(tvb, 0);
    uint8_t sacta_src_centro = tvb_get_guint8(tvb, 1);
    uint16_t sacta_src_usuario = sacta_get_gint16(pinfo, tvb, 2);

    // Obtencion del destino
    uint8_t sacta_dst_dominio = tvb_get_guint8(tvb, 4);
    uint8_t sacta_dst_centro = tvb_get_guint8(tvb, 5);
    uint16_t sacta_dst_usuario = sacta_get_gint16(pinfo, tvb, 6);

    // Saca la sacta_instancia en entornos multi-instancia (actualmente solo en el SMCT)
    uint8_t sacta_instancia = tvb_get_guint8(tvb, 8);
    // Sesion (este campo y el anterior antiguamente iban juntos)
    uint8_t sacta_sesion = tvb_get_guint8(tvb, 9);

    // Tipo de mensaje.
    uint16_t sacta_tipo = sacta_get_gint16(pinfo, tvb, 10);
    // La secuencia y las opciones estan dentro del mismo short.
    uint16_t sacta_sec_y_ops = sacta_get_gint16(pinfo, tvb, 12);
    // Los 12 bits menos significativos indican la secuencia.
    uint16_t sacta_secuencia = (sacta_sec_y_ops & 0x0FFF);
    // Los 4 bits mas significativos indican las opciones.
    uint16_t sacta_opciones = (sacta_sec_y_ops & 0x0F000) >> 12;
    // Longitud del mensaje en palabras de 16 bits.
    uint16_t sacta_short_size = sacta_get_gint16(pinfo, tvb, 14);
    // Fecha en formato UNIX
    uint32_t sacta_unix_time = sacta_get_gint32(pinfo, tvb, 16);

    bool isCompressed = (sacta_opciones & 8) != 0;

    proto_tree* cabecera_tree = proto_tree_add_subtree(sacta_tree, tvb, offset, 20, ett_sacta_src, NULL, "Cabecera SACTA");
    proto_tree* src_tree = proto_tree_add_subtree(cabecera_tree, tvb, offset, 4, ett_sacta_src, NULL, "Origen");

    uint32_t despl_src_dominio = 0;
    uint32_t despl_src_centro = 1;
    uint32_t despl_src_usuario = 2;
    uint32_t despl_dst_dominio = 4;
    uint32_t despl_dst_centro = 5;
    uint32_t despl_dst_usuario = 6;
    uint32_t despl_instancia = 8;
    uint32_t despl_sesion = 9;
    uint32_t despl_flags = 10;
    uint32_t despl_tipo = 10;
    uint32_t despl_opciones = 12;
    uint32_t despl_secuencia = 12;
    uint32_t despl_longitud = 14;
    uint32_t despl_hora = 16;
    text = get_sacta_message_field(&array_dominios, sacta_src_dominio);
    proto_tree_add_string(src_tree, hf_sacta_src_dominio, tvb, offset + despl_src_dominio, 1, text);

    text = get_sacta_message_field(&array_centros, sacta_src_centro);
    proto_tree_add_string(src_tree, hf_sacta_src_centro, tvb, offset + despl_src_centro, 1, text);

    text = get_sacta_message_field(&array_usuarios, sacta_src_usuario);
    proto_tree_add_string(src_tree, hf_sacta_src_usuario, tvb, offset + despl_src_usuario, 2, text);

    proto_tree* dst_tree = proto_tree_add_subtree(cabecera_tree, tvb, offset + despl_dst_dominio, 4, ett_sacta_dst, NULL, "Destino");

    text = get_sacta_message_field(&array_dominios, sacta_dst_dominio);
    proto_tree_add_string(dst_tree, hf_sacta_dst_dominio, tvb, offset + despl_dst_dominio, 1, text);

    text = get_sacta_message_field(&array_centros, sacta_dst_centro);
    proto_tree_add_string(dst_tree, hf_sacta_dst_centro, tvb, offset + despl_dst_centro, 1, text);

    text = get_sacta_message_field(&array_usuarios, sacta_dst_usuario);
    proto_tree_add_string(dst_tree, hf_sacta_dst_usuario, tvb, offset + despl_dst_usuario, 2, text);

    proto_tree_add_uint(cabecera_tree, hf_sacta_instancia, tvb, offset + despl_instancia, 1, sacta_instancia);

    proto_tree_add_uint(cabecera_tree, hf_sacta_sesion, tvb, offset + despl_sesion, 1, sacta_sesion);

    tipo = get_sacta_message_field(&array_tipos, sacta_tipo);
    char* isAsterix = strstr(tipo, "ASTERIX");
    char* isTracks = strstr(tipo, "TRACKS_UPDATE");
    proto_tree_add_string(cabecera_tree, hf_sacta_tipoTexto, tvb, offset + despl_tipo, 2, tipo);
    proto_tree_add_uint(cabecera_tree, hf_sacta_tipo, tvb, offset + despl_tipo, 2, sacta_tipo);

    proto_tree_add_uint(cabecera_tree, hf_sacta_opciones, tvb, offset + despl_opciones, 1, sacta_opciones);
    proto_tree_add_uint(cabecera_tree, hf_sacta_secuencia, tvb, offset + despl_secuencia, 2, sacta_secuencia);

    //proto_tree_add_uint(cabecera_tree, hf_longitud_real, tvb, 0, longitud_real, longitud_real);
    text = get_sacta_message_length(sacta_short_size);
    proto_tree_add_string(cabecera_tree, hf_sacta_longitud, tvb, offset + despl_longitud, 2, text);
    //
    proto_tree_add_uint(cabecera_tree, hf_sacta_longitud_bytes, tvb, offset + despl_longitud, 2, sacta_short_size * 2);

    nstime_t nstime;
    nstime.secs = sacta_unix_time;
    nstime.nsecs = 0;
    proto_tree_add_time(cabecera_tree, hf_sacta_fecha, tvb, offset + despl_hora, 4, &nstime);
    offset += 20;

    bool hay_cabx = existe_cabx(pinfo, tvb);
    if (hay_cabx)
    {
        proto_tree_add_boolean(cabecera_tree, hf_sacta_tipo_cabx, tvb, sacta_opciones, 2, CABX_TRUE);
    }
    else
    {
        proto_tree_add_boolean(cabecera_tree, hf_sacta_tipo_cabx, tvb, sacta_opciones, 2, CABX_FALSE);
        proto_tree_add_uint(cabecera_tree, hf_sacta_numero_cabx, tvb, sacta_opciones, 2, 0);
    }

    if (sacta_tipo == 0) {
        col_set_str(pinfo->cinfo, COL_INFO, "Msj presencia");
    }
    else
    {
        //text = get_sacta_info(&array_tipos, sacta_tipo);
        //text = (const gchar*) get_sacta_message_field(&array_tipos, sacta_tipo);

        col_set_str(pinfo->cinfo, COL_INFO, get_sacta_info(&array_tipos, sacta_tipo));
    }

    if (sacta_short_size == 0)
    {
        proto_tree_add_none_format(sacta_tree, hf_sacta_sin_datos, tvb, offset + despl_longitud, 2, "Mensaje sin datos");
    }
    else
    {
        if (isCompressed)
        {
            proto_tree_add_string(cabecera_tree, hf_datos_comprimidos, tvb, despl_flags, 2, "si");
            float ratio = (float)(100.0*((double)(longitud_real-20.0)/((double)sacta_short_size * 2.0)));
            proto_tree_add_float(cabecera_tree, hf_ratio_compresion, tvb, despl_flags, 2, ratio);
        }
        else
        {
            proto_tree_add_string(cabecera_tree, hf_datos_comprimidos, tvb, despl_flags, 2, "no");
        }

        /* A partir de aqui, si los datos estan comprimidos se descomprimen; si no lo estan no es necesario
         *  pero para comunalizar el codigo, dejan de usarse las variables tvb y offset, usandose data_tvb y data_offset
         */
        tvbuff_t* data_tvb = 0; // tvb_new_subset_remaining(tvb, offset);
        uint32_t data_offset = 0;
        if (!isCompressed)
        {
            data_tvb = tvb_new_subset_remaining(tvb, offset);
        }
        else
        {
            tvbuff_t* decomp_data_tvb = tvb_uncompress(tvb, offset, longitud_real - SACTA_HEADER_SIZE);
            if (decomp_data_tvb)
            {
                data_tvb = decomp_data_tvb;
            }
            else
            {
                proto_item* ti = proto_tree_add_item(sacta_tree, proto_sacta, tvb, 0, -1, ENC_NA);
                expert_add_info(pinfo, ti, &ei_sacta_decompression_failed);
            }
        }

        gint longitud_datos_y_cabx_sacta = tvb_reported_length_remaining(data_tvb, data_offset);
        uint16_t num_cabx = 0;
        //Ver numero de cabeceras extendidas, si las hay
        if (hay_cabx)
        {
            num_cabx = get_num_cabeceras_extendidas(pinfo, data_tvb, longitud_datos_y_cabx_sacta);
        }
        gint longitud_datos = longitud_datos_y_cabx_sacta - (TAMANO_CABX * num_cabx);

        //Procesar datos
        tvbuff_t* only_data_tvb =
            tvb_new_subset_length(data_tvb, data_offset, longitud_datos);
        add_new_data_source(pinfo, only_data_tvb, tipo);
        proto_tree_add_string(sacta_tree, hf_sacta_tipoTexto, data_tvb, data_offset, longitud_datos, tipo);

        if (asterix_handle != NULL && (isAsterix != 0 || isTracks != 0)) {
            //Get only the specified number of bytes in asterix (to avoid incorrect decoding because of SACTA padding)
            int16_t asterixLen = tvb_get_gint16(data_tvb, 1, ENC_BIG_ENDIAN);
            tvbuff_t* asterix_tvb = tvb_new_subset_length_caplen(data_tvb, data_offset, asterixLen, asterixLen);
            call_dissector(asterix_handle, asterix_tvb, pinfo, tree);
        }
        else if (xml_handle != NULL && (isXMLPacket(data_tvb, data_offset, longitud_datos, longitud_datos))) {
            //If XML packet, call wireshark XML dissector
            tvbuff_t* xml_tvb = tvb_new_subset_length_caplen(data_tvb, data_offset, longitud_datos, longitud_datos);
            call_dissector(xml_handle, xml_tvb, pinfo, tree);
        }
        else {
            //Disector de datos
            heur_dtbl_entry_t* hdtbl_entry = NULL;
            if (!dissector_try_heuristic(heur_subdissector_list, data_tvb, pinfo, tree, &hdtbl_entry, data)) {
                tvbuff_t* sacta_data_tvb = tvb_new_subset_length_caplen(data_tvb, data_offset, longitud_datos, longitud_datos);
                call_data_dissector(sacta_data_tvb, pinfo, tree);
            }
        }
        data_offset += longitud_datos;
        offset += longitud_datos;

        //Procesar cabeceras extendidas
        if (hay_cabx)
        {
            proto_tree_add_uint(cabecera_tree, hf_sacta_numero_cabx, tvb, sacta_opciones, 2, num_cabx);
            proto_tree_add_uint(cabecera_tree, hf_cabeceras_extendidas, data_tvb, data_offset, num_cabx * TAMANO_CABX, num_cabx);

            if (num_cabx != 0)
            {
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "SACTA_COMX");
                proto_tree* cabx_tree = proto_tree_add_subtree(sacta_tree, data_tvb, data_offset, TAMANO_CABX * num_cabx, 0, NULL, "Cabeceras (colas) extendidas");

                for (uint32_t i = 0; i < num_cabx; i++, data_offset += TAMANO_CABX, offset += TAMANO_CABX) {
                    uint16_t tipo_interceptor = sacta_get_gint16(pinfo, data_tvb, data_offset);
                    const char* str_tipo_interceptor = "DESCONOCIDO";
                    proto_tree* current_cabx_tree = 0;
                    uint32_t cabx_payload = data_offset + 4;

                    switch (tipo_interceptor) {
                    case TIPO_INTERCEPTOR_ARIS:

                        str_tipo_interceptor = STR_TIPO_INTERCEPTOR_ARIS;
                        current_cabx_tree = proto_tree_add_subtree(cabx_tree, data_tvb, data_offset, TAMANO_CABX, ett_cabx_aris, NULL, "Cabecera extendida");
                        proto_tree_add_string(current_cabx_tree, hf_cabx_tipo, data_tvb, data_offset, 2, STR_TIPO_INTERCEPTOR_ARIS);

                        uint16_t versionId = sacta_get_gint16(pinfo, data_tvb, cabx_payload);
                        proto_tree_add_uint(current_cabx_tree, hf_aris_version_id, data_tvb, cabx_payload, TAMANO_ARIS_VERSION_ID, versionId);

                        guint8* adaptacion = tvb_get_string_enc(wmem_packet_scope(), data_tvb, cabx_payload + TAMANO_ARIS_VERSION_ID, TAMANO_ARIS_ADAPTACION, ENC_UTF_8);
                        proto_tree_add_string(current_cabx_tree, hf_aris_adaptacion, data_tvb, cabx_payload + TAMANO_ARIS_VERSION_ID, TAMANO_ARIS_ADAPTACION, adaptacion);

                        guint8* dependencia = tvb_get_string_enc(wmem_packet_scope(), data_tvb, cabx_payload + TAMANO_ARIS_VERSION_ID + TAMANO_ARIS_ADAPTACION, TAMANO_ARIS_DEPENDENCIA, ENC_UTF_8);
                        proto_tree_add_string(current_cabx_tree, hf_aris_dependencia, data_tvb, cabx_payload + TAMANO_ARIS_VERSION_ID + TAMANO_ARIS_ADAPTACION, TAMANO_ARIS_DEPENDENCIA, dependencia);
                        break;
                    case TIPO_INTERCEPTOR_EVEREST:
                        str_tipo_interceptor = STR_TIPO_INTERCEPTOR_EVEREST;
                        current_cabx_tree = proto_tree_add_subtree(cabx_tree, data_tvb, data_offset, TAMANO_CABX, ett_cabx_eVerest, NULL, "Cabecera extendida");
                        proto_tree_add_string(current_cabx_tree, hf_cabx_tipo, data_tvb, data_offset, 2, STR_TIPO_INTERCEPTOR_EVEREST);

                        uint8_t centroOrigen = tvb_get_gint8(data_tvb, cabx_payload);
                        text = get_sacta_message_field(&array_dominios, centroOrigen);
                        proto_tree_add_string(current_cabx_tree, hf_sacta_origen_cabx, data_tvb, cabx_payload, 1, text);

                        uint8_t centroDestino = tvb_get_gint8(data_tvb, cabx_payload + 1);
                        text = get_sacta_message_field(&array_dominios, centroDestino);
                        proto_tree_add_string(current_cabx_tree, hf_sacta_destino_cabx, data_tvb, cabx_payload + 1, 1, text);
                        break;
                    case TIPO_INTERCEPTOR_AUTONOMO:
                        str_tipo_interceptor = STR_TIPO_INTERCEPTOR_AUTONOMO;
                        current_cabx_tree = proto_tree_add_subtree(cabx_tree, data_tvb, data_offset, TAMANO_CABX, ett_cabx_autonomo, NULL, "Cabecera extendida");
                        proto_tree_add_string(current_cabx_tree, hf_cabx_tipo, data_tvb, data_offset, 2, STR_TIPO_INTERCEPTOR_EVEREST);

                        uint8_t modoVigilancia = tvb_get_gint8(data_tvb, cabx_payload);
                        proto_tree_add_boolean(current_cabx_tree, hf_sacta_autonomo_mv, data_tvb, cabx_payload, 1, modoVigilancia);

                        uint8_t modoTPLV = tvb_get_gint8(data_tvb, cabx_payload + 1);
                        proto_tree_add_boolean(current_cabx_tree, hf_sacta_autonomo_mv, data_tvb, cabx_payload + 1, 1, modoTPLV);

                        uint8_t modoSMCT = tvb_get_gint8(data_tvb, cabx_payload + 2);
                        proto_tree_add_boolean(current_cabx_tree, hf_sacta_autonomo_ms, data_tvb, cabx_payload + 2, 1, modoSMCT);

                        uint8_t modoManual = tvb_get_gint8(data_tvb, cabx_payload + 3);
                        proto_tree_add_boolean(current_cabx_tree, hf_sacta_autonomo_mm, data_tvb, cabx_payload + 3, 1, modoManual);

                        break;
                    default:
                        break;
                    }
                }

            }
        }
    }

    /*
    if (isCompressed) { /-* the remainder of the packet is compressed *-/
        tvbuff_t* decomp_data_tvb = tvb_uncompress(tvb, offset, longitud_real - SACTA_HEADER_SIZE);// -(TAMANO_CABX * num_cabx));
        if (decomp_data_tvb) {
            guint32 decomp_length;
            decomp_length = tvb_captured_length(decomp_data_tvb);
            if (hay_cabx)
            {
                num_cabx = get_num_cabeceras_extendidas(pinfo, decomp_data_tvb, decomp_length);
                proto_tree_add_uint(cabecera_tree, hf_sacta_numero_cabx, tvb, sacta_opciones, 2, num_cabx);
            }
            tvbuff_t* myDecompData =
                tvb_new_subset_length(decomp_data_tvb, 0, decomp_length - (num_cabx * TAMANO_CABX));
            add_new_data_source(pinfo, myDecompData, tipo);
            proto_tree_add_uint(cabecera_tree, hf_longitud_descomprimida, tvb, offset, 2, decomp_length);
            offset = 0;
            data_tvb = tvb_new_subset_remaining(myDecompData, offset);
        }
        else {
            proto_item* ti = proto_tree_add_item(sacta_tree, proto_sacta, tvb, 0, -1, ENC_NA);
            expert_add_info(pinfo, ti, &ei_sacta_decompression_failed);
        }
        returnOffset += (longitud_real - SACTA_HEADER_SIZE);
    }
    else {
        if (hay_cabx)
        {
            num_cabx = get_num_cabeceras_extendidas(pinfo, tvb, tvb_reported_length(tvb));
            data_tvb = tvb_new_subset_length_caplen(tvb, offset, tvb_reported_length(tvb) - SACTA_HEADER_SIZE - (TAMANO_CABX * num_cabx), tvb_reported_length(tvb) - SACTA_HEADER_SIZE - (TAMANO_CABX * num_cabx));
            add_new_data_source(pinfo, data_tvb, tipo);
            returnOffset += TAMANO_CABX * num_cabx;
        }
        else
        {
            data_tvb = tvb_new_subset_remaining(tvb, offset);
            if (tvb_reported_length_remaining(tvb, offset) > 0)
            {
                add_new_data_source(pinfo, data_tvb, tipo);
            }
            returnOffset += tvb_reported_length_remaining(tvb, offset);
        }
    }

    //Si hay cabeceras extendidas, incluirlas
    offset = 0;
    gint longitud_datos_sacta = tvb_reported_length_remaining(data_tvb, offset);

    if (hay_cabx)
    {
        num_cabx = get_num_cabeceras_extendidas(pinfo, tvb, tvb_reported_length(tvb));
    }

    proto_tree_add_uint(cabecera_tree, hf_longitud_real, data_tvb, 0, longitud_real - (num_cabx * TAMANO_CABX), longitud_real - (num_cabx * TAMANO_CABX));

    if (hay_cabx)
    {
        //desde data_tvb, hasta NUM_CABX * TAM_CABX
        num_cabx = get_num_cabeceras_extendidas(pinfo, tvb, tvb_reported_length(tvb));
        proto_tree_add_uint(cabecera_tree, hf_sacta_numero_cabx, tvb, sacta_opciones, 2, num_cabx);

        uint32_t data_offset = (uint32_t)longitud_datos_sacta;
        //proto_tree_add_uint(cabecera_tree, hf_longitud_real, data_tvb, 0, longitud_datos_sacta, data_offset);
        proto_tree_add_uint(cabecera_tree, hf_cabeceras_extendidas, data_tvb, data_offset, num_cabx * TAMANO_CABX, num_cabx);

        if (num_cabx != 4)
        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "SACTA_COMX");
            proto_tree* cabx_tree = proto_tree_add_subtree(sacta_tree, data_tvb, data_offset, TAMANO_CABX * num_cabx, 0, NULL, "Cabeceras (colas) extendidas");

            //num_cabx = 0;
            for (uint32_t i = 0; i < num_cabx; i++, data_offset += TAMANO_CABX) {
                uint16_t tipo_interceptor = sacta_get_gint16(pinfo, data_tvb, data_offset);
                const char* str_tipo_interceptor = "DESCONOCIDO";
                proto_tree* current_cabx_tree = 0;
                uint32_t cabx_payload = data_offset + 4;

                switch (tipo_interceptor) {
                case TIPO_INTERCEPTOR_ARIS:

                    str_tipo_interceptor = STR_TIPO_INTERCEPTOR_ARIS;
                    current_cabx_tree = proto_tree_add_subtree(cabx_tree, data_tvb, data_offset, TAMANO_CABX, ett_cabx_aris, NULL, "Cabecera extendida");
                    proto_tree_add_string(current_cabx_tree, hf_cabx_tipo, data_tvb, data_offset, 2, STR_TIPO_INTERCEPTOR_ARIS);

                    uint16_t versionId = sacta_get_gint16(pinfo, data_tvb, cabx_payload);
                    proto_tree_add_uint(current_cabx_tree, hf_aris_version_id, data_tvb, cabx_payload, TAMANO_ARIS_VERSION_ID, versionId);

                    guint8* adaptacion = tvb_get_string_enc(wmem_packet_scope(), data_tvb, cabx_payload + TAMANO_ARIS_VERSION_ID, TAMANO_ARIS_ADAPTACION, ENC_UTF_8);
                    proto_tree_add_string(current_cabx_tree, hf_aris_adaptacion, data_tvb, cabx_payload + TAMANO_ARIS_VERSION_ID, TAMANO_ARIS_ADAPTACION, adaptacion);

                    guint8* dependencia = tvb_get_string_enc(wmem_packet_scope(), data_tvb, cabx_payload + TAMANO_ARIS_VERSION_ID + TAMANO_ARIS_ADAPTACION, TAMANO_ARIS_DEPENDENCIA, ENC_UTF_8);
                    proto_tree_add_string(current_cabx_tree, hf_aris_dependencia, data_tvb, cabx_payload + TAMANO_ARIS_VERSION_ID + TAMANO_ARIS_ADAPTACION, TAMANO_ARIS_DEPENDENCIA, dependencia);
                    break;
                case TIPO_INTERCEPTOR_EVEREST:
                    str_tipo_interceptor = STR_TIPO_INTERCEPTOR_EVEREST;
                    current_cabx_tree = proto_tree_add_subtree(cabx_tree, data_tvb, data_offset, TAMANO_CABX, ett_cabx_eVerest, NULL, "Cabecera extendida");
                    proto_tree_add_string(current_cabx_tree, hf_cabx_tipo, data_tvb, data_offset, 2, STR_TIPO_INTERCEPTOR_EVEREST);

                    uint8_t centroOrigen = tvb_get_gint8(data_tvb, cabx_payload);
                    text = get_sacta_message_field(&array_dominios, centroOrigen);
                    proto_tree_add_string(current_cabx_tree, hf_sacta_origen_cabx, data_tvb, cabx_payload, 1, text);

                    uint8_t centroDestino = tvb_get_gint8(data_tvb, cabx_payload + 1);
                    text = get_sacta_message_field(&array_dominios, centroDestino);
                    proto_tree_add_string(current_cabx_tree, hf_sacta_destino_cabx, data_tvb, cabx_payload + 1, 1, text);
                    break;
                case TIPO_INTERCEPTOR_AUTONOMO:
                    str_tipo_interceptor = STR_TIPO_INTERCEPTOR_AUTONOMO;
                    current_cabx_tree = proto_tree_add_subtree(cabx_tree, data_tvb, data_offset, TAMANO_CABX, ett_cabx_autonomo, NULL, "Cabecera extendida");
                    proto_tree_add_string(current_cabx_tree, hf_cabx_tipo, data_tvb, data_offset, 2, STR_TIPO_INTERCEPTOR_EVEREST);

                    uint8_t modoVigilancia = tvb_get_gint8(data_tvb, cabx_payload);
                    proto_tree_add_boolean(current_cabx_tree, hf_sacta_autonomo_mv, data_tvb, cabx_payload, 1, modoVigilancia);

                    uint8_t modoTPLV = tvb_get_gint8(data_tvb, cabx_payload + 1);
                    proto_tree_add_boolean(current_cabx_tree, hf_sacta_autonomo_mv, data_tvb, cabx_payload + 1, 1, modoTPLV);

                    uint8_t modoSMCT = tvb_get_gint8(data_tvb, cabx_payload + 2);
                    proto_tree_add_boolean(current_cabx_tree, hf_sacta_autonomo_ms, data_tvb, cabx_payload + 2, 1, modoSMCT);

                    uint8_t modoManual = tvb_get_gint8(data_tvb, cabx_payload + 3);
                    proto_tree_add_boolean(current_cabx_tree, hf_sacta_autonomo_mm, data_tvb, cabx_payload + 3, 1, modoManual);

                    break;
                default:
                    break;
                }
            }
          
        } 
    }
    uint16_t dataLen = tvb_reported_length_remaining(data_tvb, offset);
    if (dataLen > 0)
    {
        //proto_tree* datos_tree = proto_tree_add_subtree_format(sacta_tree, data_tvb, offset, dataLen, ett_sacta_datos, NULL, "Datos (%d bytes)", dataLen);
        proto_tree_add_string(sacta_tree, hf_sacta_tipoTexto, data_tvb, offset, dataLen, tipo);
    }
    */

    //Clear fragmentation data
    pinfo->fragmented = save_fragmented;

    return offset;
}

void proto_register_sacta(void) {
    printf("Register SACTA dissector \n");
    reassembly_table_register(&msg_reassembly_table,
        &addresses_ports_reassembly_table_functions);
    reassembly_table_init(&msg_reassembly_table,
        &addresses_ports_reassembly_table_functions);

    array_dominios = array_string_create();
    array_centros = array_string_create();
    array_usuarios = array_string_create();
    array_tipos = array_string_create();

    char* sacta_config_path = getenv("SACTA_CONFIG_PATH");
    if (sacta_config_path == 0) {
        sacta_config_path = ".";
    }

    if (sacta_config_path) {
        char path[PATH_SIZE];

        snprintf(path, sizeof(path), "%s/COM_IP_CENTROS.CFG", sacta_config_path);


        int dominios = dominios_read(path, &array_dominios);
        if (dominios > 0) {
            printf("Dominios: %d \n", dominios);
        }

        int centros = centros_read(path, &array_centros);
        if (centros > 0) {
            printf("Centros: %d \n", centros);
        }

        snprintf(path, sizeof(path), "%s/COM_USUARIOS.CFG", sacta_config_path);

        int usuarios = usuarios_read(path, &array_usuarios);
        if (usuarios > 0) {
            printf("Usuarios: %d \n", usuarios);
        }

        snprintf(path, sizeof(path), "%s/q_gen_mensa.idl", sacta_config_path);

        int tipos = tipos_read(path, &array_tipos);
        if (tipos > 0) {
            printf("Tipos: %d \n", tipos);
        }
    }
    else {
        fprintf(stderr, "WARNING: la variable de entorno \"SACTA_CONFIG_PATH\" no esta definida.\n");
    }

    proto_sacta = proto_register_protocol("SACTA Protocol", "sacta", "sacta");
    proto_register_field_array(proto_sacta, hf_sacta, array_length(hf_sacta));
    proto_register_subtree_array(ett_sacta, array_length(ett_sacta));

    module_t* sacta_module = prefs_register_protocol(proto_sacta, NULL);
    heur_subdissector_list = register_heur_dissector_list("sacta", proto_sacta);
    prefs_register_bool_preference(sacta_module, "heur",
        "Use heuristics for calculate if a UDP message is SACTA Protocol",
        "Use heuristics for calculate if a UDP message is SACTA Protocol",
        &sacta_heur
    );
}

void proto_reg_handoff_sacta(void) {
    dissector_handle_t sacta_handle;
    heur_dissector_t heuristic_dissector_function = dissect_sacta_heur_udp;
    asterix_handle = find_dissector_add_dependency("asterix", proto_sacta);
    xml_handle = find_dissector_add_dependency("xml", proto_sacta);
    sacta_handle = create_dissector_handle(dissect_fragmented_sacta, proto_sacta);
    dissector_add_uint_with_preference("udp.port", SACTA_UDP_PORT, sacta_handle);
    heur_dissector_add("udp", heuristic_dissector_function, "sacta over UDP", "sacta_udp", proto_sacta, HEURISTIC_ENABLE);
}
