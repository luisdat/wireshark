/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-lppa.h                                                              */
/* asn2wrs.py -L -p lppa -c ./lppa.cnf -s ./packet-lppa-template -D . -O ../.. LPPA-CommonDataTypes.asn LPPA-Constants.asn LPPA-Containers.asn LPPA-IEs.asn LPPA-PDU-Contents.asn LPPA-PDU-Descriptions.asn */

/* Input file: packet-lppa-template.h */

#line 1 "./asn1/lppa/packet-lppa-template.h"
/* packet-lppa.h
 * Routines for 3GPP LTE Positioning Protocol A (LLPa) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LPPA_H
#define PACKET_LPPA_H

typedef struct _lppa_ctx_t {
  guint32 message_type;
  guint32 ProcedureCode;
  guint32 ProtocolIE_ID;
  guint32 ProtocolExtensionID;
} lppa_ctx_t;



/*--- Included file: packet-lppa-exp.h ---*/
#line 1 "./asn1/lppa/packet-lppa-exp.h"

/*--- End of included file: packet-lppa-exp.h ---*/
#line 23 "./asn1/lppa/packet-lppa-template.h"

#endif  /* PACKET_LPPA_H */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
