
/*
 * packet-sacta.h
 *
 *  Created on: 12 jun. 2019
 *      Author: gromerov
 */

#ifndef PACKET_SACTA_H
#define PACKET_SACTA_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/nstime.h>
/*
#include "packet-sacta-dominios.h"
#include "packet-sacta-centros.h"
#include "packet-sacta-usuarios.h"
#include "packet-sacta-tipos.h"
#include "packet-sacta-opciones.h"
*/
#include "packet-sacta-utils.h"

void proto_register_sacta(void);
void proto_reg_handoff_sacta(void);

#endif
