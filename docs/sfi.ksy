meta:
  id: sfi
  file-extension: sfi
  endian: le
  encoding: ascii

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

  # Shared across OS and app images.
  image_header:
    seq:
      - id: identifier
        doc: |-
          TODO: What _does_ this mean?
          This appears to vary between BlackBerries.
        type: u4
      - id: code_start
        type: u4
      - id: code_end
        type: u4


  # TODO: There's a lot more information here!
  # We only implement what we need.
  image_info:
    seq:
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
      - id: unknown
        type: u4
      - id: app_main_addr
        type: u4

  ############
  # OS Image #
  ############
  os_image_contents:
    seq:
      - id: header
        type: image_header
      - id: code
        # Code is end - start - header size
        size: header.code_end - header.code_start - 24
      - id: info
        type: image_info
        # TODO: Hardcoded around info
      - id: padding
        size: info.app_main_addr - header.code_end - 20 - 120

  app_image_contents:
    seq:
      - id: header
        type: image_header
      - id: code
        # Code is end - start - header size
        size: header.code_end - header.code_start - 24

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
