# name: attributes for -march=armv6kt2
# source: blank.s
# as: -march=armv6kt2
# readelf: -A
# This test is only valid on EABI based ports.
# target: *-*-*eabi

Attribute Section: aeabi
File Attributes
  Tag_CPU_name: "6KT2"
  Tag_CPU_arch: v6T2
  Tag_ARM_ISA_use: Yes
  Tag_THUMB_ISA_use: Thumb-2
  Tag_DIV_use: Not allowed
