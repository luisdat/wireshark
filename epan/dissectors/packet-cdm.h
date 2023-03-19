#ifndef PACKET_CDM_H
#define PACKET_CDM_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/nstime.h>

void proto_register_cdmproto(void);
void proto_reg_handoff_cdmproto(void);

#endif
