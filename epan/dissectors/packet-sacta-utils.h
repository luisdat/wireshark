/*
 * packet-sacta-utils.h
 *
 *  Created on: 12 jun. 2019
 *      Author: gromerov
 */

#ifndef PACKET_SACTA_UTILS_H
#define PACKET_SACTA_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
//#include <ctype.h>
//#include <string.h>
#include <sys/types.h>
//#include <sys/stat.h>
//#include <unistd.h> NOT IN WINDOWS

typedef struct {
	char ** ptr;
	uint32_t size;
} array_string;

array_string array_string_create(void);
const char * array_string_get(array_string * array, uint32_t index);
void array_string_free(array_string * list);

int dominios_read(const char * filename, array_string * array);
int centros_read(const char * filename, array_string * array);
int usuarios_read(const char * filename, array_string * array);
int tipos_read(const char * filename, array_string * array);

#endif
