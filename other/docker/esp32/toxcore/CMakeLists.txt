set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers")

file(GLOB toxcore_SRCS "toxcore/*.[ch]" "toxcore/*/*.[ch]")
set(COMPONENT_SRCS
  ${toxcore_SRCS}
  other/docker/esp32/main/toxcore_main.cc
  third_party/cmp/cmp.c
  third_party/cmp/cmp.h
  toxencryptsave/defines.h)
set(COMPONENT_ADD_INCLUDEDIRS "")

register_component()
