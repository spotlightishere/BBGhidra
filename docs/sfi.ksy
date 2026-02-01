meta:
  id: sfi
  file-extension: sfi
  endian: le
  encoding: ASCII

seq:
  - id: magic
    contents: [0x7d, 0x79, 0xab, 0x59]
  - id: format_version
    type: u4
    doc: |-
      Unclear. Newer firmware appears to be 0x10008 and above.
      Presumably dictates features of this SFI and/or hardware version?
  - id: image_file_type
    type: u4
    enum: image_file_type
  - id: total_length
    type: u4
    doc: The length of this entire segment, including header.
  - id: identifier
    type: u4
    doc: |-
      TODO: What _does_ this mean?
      This appears to vary between BlackBerries.
  - id: version
    type: version
  - id: contents
    type:
      switch-on: image_file_type
      cases:
        'image_file_type::os_image_file': os_image_file
types:
  ###################
  # SFI format type #
  ###################
  os_image_file:
    seq:
      - id: armv6_vectors
        type: armv6_vectors
        doc: Standard exception vectors.
      - id: image_count_maybe
        type: u4
      - id: os_image
        type: os_image_contents
      - id: app_image
        type: app_image_contents

  ###########
  # Generic #
  ###########

  os_image_header:
    seq:
      - id: base_addr
        type: u4
      - id: build_info_addr
        type: u4

  # TODO: There's a lot more information here!
  # We only implement what we need.
  os_image_info:
    seq:
      - id: first_addr
        type: u4
      - id: second_addr
        type: u4
      - id: heap_end_addr
        type: u4
      - id: build_user
        type: strz
        size: 16
      - id: build_date
        type: strz
        size: 12
      - id: build_year
        type: strz
        size: 12
      - id: device_name
        type: strz
        size: 64
      - id: device_identifier
        type: u4
      - id: version
        type: version

  ############
  # OS Image #
  ############
  # This refers to the stub OS image present
  # at the start of the SFI, and not the
  # full, uncompressed underlying Qualcomm app OS.
  os_image_contents:
    seq:
      - id: header
        type: os_image_header
      - id: code
        # Code is end - start - header size
        size: header.build_info_addr - header.base_addr - 20 - 20 - 8
      - id: whole_length
        type: u4
      - id: info_version
        type: u4
        doc: Not entirely certain this is true.
      - id: info_length
        type: u4
      - id: os_info
        type: os_image_info

      # TODO: This segment seems to contain a lot of
      # information regarding memory layout, and versions.
      #
      # We are interested in one value: our compressed loader offset.
      - id: skipped_fields
        type: u4
        repeat: expr
        repeat-expr: 19

      - id: loader_addr
        type: u4
      - id: loader_length_maybe
        type: u4

      # We're skipping over the remainder currently as layout
      # appears volatile across OS versions with no clear pattern.
      #
      # Repeat until we encounter the app image magic, 0x1F2DCCD7.
      - id: ignored_fields
        type: u4
        repeat: until
        repeat-until: _ == 3620482335


  app_image_header:
    seq:
      - id: base_addr
        type: u4
      - id: build_info_addr
        type: u4
      - id: loader_addr
        type: u4

  app_image_info:
    seq:
      - id: info_version
        type: u4

  app_image_contents:
    seq:
      - id: header
        type: app_image_header
      - id: code
        # Code is end - start - header size
        # We use the base address from our OS segment, which
        # should theoretically be 0x10000000.
        size: header.loader_addr - header.base_addr - 12
      - id: segment_length_maybe
        type: u4
        # TODO: This appears to extend beyond both images.
        # Something else may be required.
      - id: segment_contents
        size: segment_length_maybe

  version:
    doc: -|
      General version type used in many places.
      If major is 4, minor is 2, and patch is 451,
      this would generally be shown as "4.2.0.451".
    seq:
      - id: patch_version
        type: u2
      - id: minor_version
        type: u1
      - id: major_version
        type: u1

  ############
  # Niceties #
  ############
  armv6_vectors:
    doc: https://developer.arm.com/documentation/100748/0613/embedded-software-development/vector-table-for-armv6-and-earlier--armv7-a-and-armv7-r-profiles
    seq:
      - id: reset
        type: u4
      - id: undefined
        type: u4
      - id: svc
        type: u4
      - id: prefetch
        type: u4
      - id: abort
        type: u4
      - id: reserved
        type: u4
      - id: irq
        type: u4
enums:
  image_file_type:
    2: os_image_file
