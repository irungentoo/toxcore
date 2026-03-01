set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers -Wno-format -DMIN_LOGGER_LEVEL=LOGGER_LEVEL_TRACE")

file(GLOB toxcore_SRCS "toxcore/*.[ch]" "toxcore/*/*.[ch]")
set(COMPONENT_SRCS
  ${toxcore_SRCS}
  other/docker/esp32/main/app_main.cc
  other/docker/esp32/main/tox_main.cc
  other/docker/esp32/main/tox_main.h
  third_party/cmp/cmp.c
  third_party/cmp/cmp.h
  toxencryptsave/defines.h)

idf_component_register(
  SRCS ${COMPONENT_SRCS}
  INCLUDE_DIRS "."
  REQUIRES esp_eth esp_netif lwip)
