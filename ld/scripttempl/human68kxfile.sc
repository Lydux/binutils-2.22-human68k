test -z "$ENTRY" && ENTRY=_start
INIT='.init : { *(.init) }'
FINI='.fini : { *(.fini) }'
CTORS='.ctors : { *(.ctors) }'
DTORS='.dtors : { *(.dtors) }'

cat <<EOF
OUTPUT_FORMAT("${OUTPUT_FORMAT}")
${LIB_SEARCH_DIRS}

${RELOCATING+ENTRY (${ENTRY})}

SECTIONS
{
  .text ${RELOCATING+ ${TEXT_START_ADDR}} : {

    ${RELOCATING+ *(.init)}
    *(.text)
    *(.text.*)

    ${RELOCATING+ *(.fini)} 
    ${RELOCATING+. = ALIGN (4);}
    ${RELOCATING+ etext = .;}
    ${RELOCATING+ _etext = .;}
  }

  .data ${RELOCATING+ SIZEOF(.text) + ADDR(.text)} :
  {
    ${CONSTRUCTING+ __ctors_start = . ; }
    ${CONSTRUCTING+ *(.ctors) }
    ${CONSTRUCTING+ __ctors_end = . ; }
    ${CONSTRUCTING+ __dtors_start = . ; }
    ${CONSTRUCTING+ *(.dtors) }
    ${CONSTRUCTING+ __dtors_end = . ; }
    KEEP(SORT(*)(.ctors))
    KEEP(SORT(*)(.dtors))

    *(.data)
    *(.data*)
    *(.rodata)  /* We need to include .rodata here if gcc is used */
    *(.rodata*) /* with -fdata-sections.  */

    ${RELOCATING+*(.gcc_exc*)}
    ${RELOCATING+___EH_FRAME_BEGIN__ = . ;}
    ${RELOCATING+*(.eh_fram*)}
    ${RELOCATING+___EH_FRAME_END__ = . ;}

    ${RELOCATING+. = ALIGN (4);}
    ${RELOCATING+ edata = .;}
    ${RELOCATING+ _edata = .;}
  }
  .bss ${RELOCATING+ SIZEOF(.data) + ADDR(.data)} :
  {
    *(.bss)
    *(COMMON)
    ${RELOCATING+. = ALIGN (2);}
    ${RELOCATING+ end = .;}
    ${RELOCATING+ _end = .;}
  }
  ${RELOCATING- ${INIT}}
  ${RELOCATING- ${FINI}}
  ${RELOCATING- ${CTORS}}
  ${RELOCATING- ${DTORS}}

  .comment 0 ${RELOCATING+(NOLOAD)} : { [ .comment ] [ .ident ] }
  .stab 0 ${RELOCATING+(NOLOAD)} : { [ .stab ] }
  .stabstr 0 ${RELOCATING+(NOLOAD)} : { [ .stabstr ] }
}
EOF

