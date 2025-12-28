meta:
  # BootInfo format in okL4.
  # For BlackBerry purposes, this
  # TODO: Figure this out
  id: bootinfo
  file-extension: mapping
  endian: le
  encoding: ASCII
seq:
  - id: entries
    type: op_entry
    repeat: until
    repeat-until: _.type == op_types::op_end

types:
  ##############
  # Base types #
  ##############
  op_entry:
    seq:
      - id: word_count
        type: u2
        doc: Byte size of this entire entry.
      - id: type
        type: u2
        enum: op_types
      - id: contents
        # The entry header consumes one word.
        size: (word_count - 4)
        type:
          switch-on: type
          cases:
            'op_types::op_header': header_format
            # op_end has no contents, and is a special case.
            'op_types::op_add_new_pd': add_new_pd
            'op_types::op_add_new_ms': add_new_ms
            'op_types::op_add_virt_mem': mem_pool_layout
            'op_types::op_add_phys_mem': mem_pool_layout
            'op_types::op_new_thread': new_thread
            'op_types::op_run_thread': run_thread
            'op_types::op_map': map_segment
            'op_types::op_attach': attach
            'op_types::op_grant': grant
            'op_types::op_register_server': pd_ms_pair
            'op_types::op_register_callback': pd_ms_pair
            'op_types::op_register_stack': thread_ms_pair
            'op_types::op_init_mem': init_mem
            'op_types::op_new_cap': capability
            'op_types::op_grant_cap': grant_cap
            'op_types::op_object_export': object_export
            'op_types::op_struct_export': struct_export
            'op_types::op_register_env': thread_ms_pair
            'op_types::op_new_pool': new_pool

            # These go unused in OKL4 2.1.1.
            # 'op_types::op_new_vm_pool': u4
            # 'op_types::op_new_phys_pool': u4

            # These types were not observed,
            # and thus cannot be validated.
            # 'op_types::op_export': u4
            # 'op_types::op_argv': u4
            # 'op_types::op_grant_interrupt': u4
            # 'op_types::op_security_control': u4
            # 'op_types::op_new_zone': u4
            # 'op_types::op_add_zone_window': u4
            # 'op_types::op_kernel_info': u4


  ############################
  # Operation-specific types #
  ############################
  header_format:
    seq:
      - id: magic
        doc: |-
          This is 0x1960021d in big-endian notation.
          This value is little-endian for our purposes.
        contents: [0x1d, 0x02, 0x60, 0x19]
      - id: version
        type: u4
        doc: Only version 8 was found publicly, but this is 7.
      - id: is_debug
        type: u4

  init_mem:
    seq:
      - id: stack_base
        type: u4
      - id: stack_end
        type: u4
      - id: heap_base
        type: u4
      - id: heap_end
        type: u4

  mem_pool_layout:
    seq:
      - id: pool
        type: u4
      - id: base_addr
        type: u4
      - id: end_addr
        type: u4

  new_pool:
    seq:
      - id: is_virtual
        type: u4

  add_new_pd:
    seq:
      - id: owner
        type: u4

  capability:
    seq:
      - id: object
        type: u4
      - id: rights
        type: u4
        enum: capabilities

  add_new_ms:
    seq:
      - id: owner
        type: u4
      - id: base
        type: u4
      - id: size
        type: u4
      - id: flags
        type: u4
      - id: attr
        type: u4
      - id: physpool
        type: u4
      - id: virtpool
        type: u4
      - id: zone
        type: u4
        doc: If 0xFF, then this is ignored.
      - id: name
        type: strz
        size-eos: true


  attach:
    seq:
      - id: pd
        type: u4
      - id: memory_section
        type: u4
      - id: rights
        type: u4
        enum: access_rights

  grant:
    seq:
      - id: pd
        type: u4
      - id: memory_section
        type: u4
      - id: cap
        type: u4
        enum: capabilities

  grant_cap:
    seq:
      - id: pd
        type: u4
      - id: cap
        type: u4
        enum: capabilities

  map_segment:
    seq:
      - id: vaddr
        type: u4
      - id: size
        type: u4
      - id: paddr
        type: u4
      - id: scrub
        type: u4
      - id: mode
        type: u4

  pd_ms_pair:
    seq:
      - id: pd
        type: u4
      - id: memory_section
        type: u4

  thread_ms_pair:
    seq:
      - id: thread
        type: u4
      - id: memory_section
        type: u4

  new_thread:
    seq:
      - id: owner
        type: u4
      - id: ip
        type: u4
      - id: user_main
        type: u4
      - id: priority
        type: u4
      - id: name
        type: strz
        size-eos: true

  object_export:
    seq:
      - id: pd
        type: u4
      - id: object
        type: u4
      - id: type
        type: u4
      - id: name
        type: strz
        size-eos: true

  struct_export:
    seq:
      - id: pd
        type: u4
      - id: first
        type: u4
      - id: second
        type: u4
      - id: third
        type: u4
      - id: fourth
        type: u4
      - id: fifth
        type: u4
      - id: sixth
        type: u4
      - id: type
        type: u4
      - id: id
        doc: Maybe?
        type: u4
      - id: name
        type: strz
        size-eos: true

  run_thread:
    seq:
      - id: name
        type: u4

enums:
  op_types:
    1: op_header
    2: op_end
    3: op_add_new_pd
    4: op_add_new_ms
    5: op_add_virt_mem
    6: op_add_phys_mem
    7: op_new_thread
    8: op_run_thread
    9: op_map
    10: op_attach
    11: op_grant
    12: op_export
    13: op_argv
    14: op_register_server
    15: op_register_callback
    16: op_register_stack
    17: op_init_mem
    18: op_new_vm_pool
    19: op_new_phys_pool
    20: op_new_cap
    21: op_grant_cap
    22: op_object_export
    23: op_struct_export
    24: op_register_env
    25: op_new_pool
    26: op_grant_interrupt
    27: op_security_control
    28: op_new_zone
    29: op_add_zone_window
    30: op_kernel_info

  access_rights:
    0: no_access
    1: executable
    2: writable
    4: readable

  capabilities:
    1: execute
    2: write
    4: read
