#ifndef PACKET_4SIGHT_H
#define PACKET_4SIGHT_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/nstime.h>

void proto_register_4sightproto(void);
void proto_reg_handoff_4sightproto(void);

#endif
