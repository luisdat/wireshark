/*
 * packet-sacta-utils.c
 *
 *  Created on: 12 jun. 2019
 *      Author: gromerov
 */

#ifdef _MSC_VER
   #define _CRT_SECURE_NO_WARNINGS 1
   #define restrict __restrict
#endif
 
#include "packet-sacta-utils.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

/*
POSIX getline replacement for non-POSIX systems (like Windows)
Differences:
    - the function returns int64_t instead of ssize_t
    - does not accept NUL characters in the input file
Warnings:
    - the function sets EINVAL, ENOMEM, EOVERFLOW in case of errors. The above are not defined by ISO C17,
    but are supported by other C compilers like MSVC
*/
static int64_t my_getline(char **restrict line, size_t *restrict len, FILE *restrict fp) {
    // Check if either line, len or fp are NULL pointers
    if(line == NULL || len == NULL || fp == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    // Use a chunk array of 128 bytes as parameter for fgets
    char chunk[128];

    // Allocate a block of memory for *line if it is NULL or smaller than the chunk array
    if(*line == NULL || *len < sizeof(chunk)) {
        *len = sizeof(chunk);
        if((*line = malloc(*len)) == NULL) {
            errno = ENOMEM;
            return -1;
        }
     }
 
    // "Empty" the string
    (*line)[0] = '\0';

    while(fgets(chunk, sizeof(chunk), fp) != NULL) {
        // Resize the line buffer if necessary
        size_t len_used = strlen(*line);
        size_t chunk_used = strlen(chunk);

        if(*len - len_used < chunk_used) {
            // Check for overflow
            if(*len > SIZE_MAX / 2) {
                errno = EOVERFLOW;
                return -1;
            } else {
                *len *= 2;
            }
            
            if((*line = realloc(*line, *len)) == NULL) {
                errno = ENOMEM;
                return -1;
            }
        }

        // Copy the chunk to the end of the line buffer
        memcpy(*line + len_used, chunk, chunk_used);
        len_used += chunk_used;
        (*line)[len_used] = '\0';

        // Check if *line contains '\n', if yes, return the *line length
        if((*line)[len_used - 1] == '\n') {
            return len_used;
        }
    }

    return -1;
}

#define WORD_SIZE        64
#define WORD_SIZE_FMT  "%63s"  // Reserve one byte for the end of string '\0'

typedef struct _node_index_string {
	uint32_t index;
	char * s_ptr;
	uint32_t s_size;
	struct _node_index_string * next_ptr;
} node_index_string;

typedef struct {
	node_index_string * head;
	node_index_string * tail;
	uint32_t max_index;
} list_index_string;

list_index_string list_index_string_create(void);
bool list_index_string_add(list_index_string * list, uint32_t index, const char * string);
bool list_index_string_to_array_string(list_index_string * list, array_string * array);
void list_index_string_free(list_index_string * list);
bool is_comment_line(char * string);

list_index_string list_index_string_create(void) {
	list_index_string list;
	list.head = NULL;
	list.tail = NULL;
	list.max_index = 0;
	return list;
}

bool list_index_string_add(list_index_string * list, uint32_t index, const char * string) {
	if(list != NULL && string != NULL) {

		node_index_string * new_node = (node_index_string *) calloc(1, sizeof(node_index_string));
		new_node->index = index;
		new_node->s_size = (uint32_t) strlen(string);
		new_node->s_ptr = (char *) calloc(new_node->s_size + 1, sizeof(char));
		strncpy(new_node->s_ptr, string, new_node->s_size + 1);

		if(list->head == NULL && list->tail == NULL) {
			// First element
			list->head = new_node;
			list->tail = new_node;
		} else {
			// Insert to the end.
			list->tail->next_ptr = new_node;
			// Update list->tail pointer.
			list->tail = new_node;
		}

		// Update max_index
		list->max_index = (list->max_index < new_node->index) ? new_node->index : list->max_index;

		return true;
	} else {
		return false;
	}
}

bool list_index_string_to_array_string(list_index_string * list, array_string * array) {
	if(list != NULL && array != NULL) {

		array->size = list->max_index + 1;
		array->ptr = (char **) calloc(array->size, sizeof(char *)); // Automatic NULL pointer initializacion.

		node_index_string * step_ptr = list->head;
		while(step_ptr != NULL) {

			uint32_t index = step_ptr->index;

			array->ptr[index] = (char *) calloc(step_ptr->s_size + 1, sizeof(char));
			strncpy(array->ptr[index], step_ptr->s_ptr, step_ptr->s_size + 1);

			step_ptr = step_ptr->next_ptr;
		}

		return true;
	} else {
		return false;
	}
}

void list_index_string_free(list_index_string * list) {
	node_index_string * del_ptr = NULL;

	while(list->head != NULL) {
		del_ptr = list->head;
		list->head = list->head->next_ptr;
		free(del_ptr->s_ptr);
		free(del_ptr);
	}
	list->head = NULL;
	list->tail = NULL;
	list->max_index = 0;
}

array_string array_string_create(void) {
	array_string array;

	array.ptr = NULL;
	array.size = 0;

	return array;
}

const char * array_string_get(array_string * array, uint32_t index) {
	if(index < array->size) {
		return array->ptr[index];
	} else {
		return NULL;
	}
}

void array_string_free(array_string * array) {
	for(uint32_t i=0; i<array->size; i++) {
		if(array->ptr[i] != NULL) {
			free(array->ptr[i]);
		}
	}
	free(array->ptr);
	array->size = 0;
}

bool is_comment_line(char * string) {
	size_t s_size = strlen(string);

	for(size_t i=0; i<s_size; i++) {
		if(isspace(string[i])) {
			continue;
		} else if(string[i] == '#') {
			return true;
		} else {
			break;
		}
	}

	return false;
}

int dominios_read(const char * filename, array_string * array) {
	FILE * fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "IO ERROR: No se ha podido abrir el fichero \"%s\".\n", filename);
		return false;
	}

	int index;
	char s_name[WORD_SIZE];
	char s_garbage[WORD_SIZE];

	char * line = NULL;
	size_t len = 0;

	list_index_string list = list_index_string_create();
	int count_line = 0;
	int items_read = 0;
	while (my_getline(&line, &len, fp) != -1) {
		count_line++;

		if(len == 0) {
			continue;
		}

		if(is_comment_line(line)) {
			continue;
		}

		if(strstr(line, "DOMINIO ") != NULL) {

			// Example: "DOMINIO 1 SACTA 10.0.0.0"
			int retval = sscanf(line, WORD_SIZE_FMT " %d "WORD_SIZE_FMT " " WORD_SIZE_FMT, s_garbage, &index, s_name, s_garbage);
			if(retval > 0) {
				list_index_string_add(&list, index, s_name);
				items_read++;

			} else {
				fprintf(stderr, "PARSE ERROR: fichero: \"%s\", linea: %d, \"%s\".\n", filename, count_line, line);
			}
		}
	}

	if (line) {
		free(line);
	}

	// Convert list to array
	list_index_string_to_array_string(&list, array);
	list_index_string_free(&list);

	return items_read;
}

int centros_read(const char * filename, array_string * array) {
	FILE * fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "IO ERROR: No se ha podido abrir el fichero \"%s\".\n", filename);
		return false;
	}

	int index;
	char s_name[WORD_SIZE];
	char s_garbage[WORD_SIZE];

	char * line = NULL;
	size_t len = 0;

	list_index_string list = list_index_string_create();
	int count_line = 0;
	int items_read = 0;
	while (my_getline(&line, &len, fp) != -1) {
		count_line++;

		if(len == 0) {
			continue;
		}
		if(is_comment_line(line)) {
			continue;
		}

		if(strstr(line, "ID ") != NULL) {

			// Example: "ID 1 ACC_LECM"
			int retval = sscanf(line, WORD_SIZE_FMT " %d " WORD_SIZE_FMT, s_garbage, &index, s_name);
			if(retval > 0) {
				list_index_string_add(&list, index, s_name);
				items_read++;

			} else {
				fprintf(stderr, "PARSE ERROR: fichero: \"%s\", linea: %d, \"%s\".\n", filename, count_line, line);
			}
		}
	}

	if (line) {
		free(line);
	}

	// Convert list to array
	list_index_string_to_array_string(&list, array);
	list_index_string_free(&list);

	return items_read;
}

int usuarios_read(const char * filename, array_string * array) {
	FILE * fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "IO ERROR: No se ha podido abrir el fichero \"%s\".\n", filename);
		return false;
	}

	int index;
	char s_name[WORD_SIZE];

	char * line = NULL;
	size_t len = 0;

	list_index_string list = list_index_string_create();
	int count_line = 0;
	int items_read = 0;
	while (my_getline(&line, &len, fp) != -1) {
		count_line++;

		if(len == 0) {
			continue;
		}
		if(is_comment_line(line)) {
			continue;
		}

		char * eq_ptr = strstr(line, "=");
		if(eq_ptr != NULL) {
			eq_ptr[0] = ' ';

			// Example: "ENTRAD_ALL = 1"
			int retval = sscanf(line, WORD_SIZE_FMT " %d", s_name, &index);
			if(retval > 0) {
				list_index_string_add(&list, index, s_name);
				items_read++;

			} else {
				fprintf(stderr, "PARSE ERROR: fichero: \"%s\", linea: %d, \"%s\".\n", filename, count_line, line);
			}
		}
	}

	if (line) {
		free(line);
	}

	// Convert list to array
	list_index_string_to_array_string(&list, array);
	list_index_string_free(&list);

	return items_read;
}

int tipos_read(const char * filename, array_string * array) {
	FILE * fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "IO ERROR: No se ha podido abrir el fichero \"%s\".\n", filename);
		return false;
	}

	int index;
	char s_name[WORD_SIZE];
	char s_garbage[WORD_SIZE];

	char * line = NULL;
	size_t len = 0;

	list_index_string list = list_index_string_create();
	int count_line = 0;
	int items_read = 0;
	bool comment_mode = false;
	while (my_getline(&line, &len, fp) != -1) {
		count_line++;

		if(len == 0) {
			continue;
		}

		// Discard inline comments
		if(line[0] == '/' && line[1] == '/') {
			continue;
		}
		// Discard multiline comments
		if(strstr(line, "/*") != NULL) {
			comment_mode = true;
		}
		if(strstr(line, "*/") != NULL) {
			comment_mode = false;
		}
		if(comment_mode) {
			continue;
		}

		char * const_ptr = strstr(line, "const ");
		char * short_ptr = strstr(line, " short ");
		char * eq_ptr = strstr(line, "=");
		char * dc_ptr = strstr(line, ";");
		if(const_ptr < short_ptr && short_ptr < eq_ptr && eq_ptr < dc_ptr) {
			eq_ptr[0] = ' ';
			dc_ptr[0] = ' ';

			// Example: "const short C_PETICION_DE_INICIO_PDR = 1;"
			int retval = sscanf(line, WORD_SIZE_FMT " " WORD_SIZE_FMT " " WORD_SIZE_FMT " %d", s_garbage, s_garbage, s_name, &index);

			if(retval > 0) {
				list_index_string_add(&list, index, s_name);
				items_read++;

			} else {
				fprintf(stderr,"PARSE ERROR: fichero: \"%s\", linea: %d, \"%s\".\n", filename, count_line, line);
			}
		}
	}
	fprintf(stderr,"PARSE finalizado: fichero: \"%s\"\n", filename);

	if (line) {
		 free(line);
	}

	// Convert list to array
	list_index_string_to_array_string(&list, array);
	list_index_string_free(&list);

	return items_read;
}
