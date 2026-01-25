# =============================================================================
# IndraATM.cmake
# Deploy necessary configuration files for the IndraATM dissector
# =============================================================================

message(STATUS "[IndraATM] Deploying configuration files...")

set(INDRA_CONFIG_FILES
    "${CMAKE_SOURCE_DIR}/COM_USUARIOS.CFG"
    "${CMAKE_SOURCE_DIR}/COM_IP_CENTROS.CFG"
    "${CMAKE_SOURCE_DIR}/q_gen_mensa.idl"
)

set(INDRA_DESTINATIONS
    "${CMAKE_BINARY_DIR}"
    "${CMAKE_BINARY_DIR}/run"
)

if(MSVC OR CMAKE_CONFIGURATION_TYPES)
    list(APPEND INDRA_DESTINATIONS 
        "${CMAKE_BINARY_DIR}/run/RelWithDebInfo"
        "${CMAKE_BINARY_DIR}/run/Debug"
    )
endif()

foreach(DEST_PATH ${INDRA_DESTINATIONS})
    file(COPY ${INDRA_CONFIG_FILES} DESTINATION "${DEST_PATH}")
endforeach()

message(STATUS "[IndraATM] Configuration files copied successfully.")