test -z "$ENTRY" && ENTRY=_start

INIT='.init : { *(.init) }'
FINI='.fini : { *(.fini) }'

cat <<EOF
OUTPUT_FORMAT("${OUTPUT_FORMAT}")
OUTPUT_ARCH(${ARCH})
${LIB_SEARCH_DIRS}

${RELOCATING+ENTRY (${ENTRY})}

SECTIONS
{
  .text ${RELOCATING+ SIZEOF_HEADERS} : {
    ${RELOCATING+ PROVIDE (_init_start = .);}
    ${RELOCATING+ PROVIDE (_init = .);}
    ${RELOCATING+ KEEP (*(.init))}
    ${RELOCATING+ PROVIDE (_init_end = .);}

    *(.text)

    ${RELOCATING+ PROVIDE (_fini_start = .);}
    ${RELOCATING+ PROVIDE (_fini = .);}
    ${RELOCATING+ KEEP (*(.fini))}
    ${RELOCATING+ PROVIDE (_fini_end = .);}

    ${RELOCATING+ etext  =  .};
  }
  .data ${RELOCATING+ SIZEOF(.text) + ADDR(.text)} : {
    *(.data)
    ${RELOCATING+ edata  =  .};
  }
  .bss ${RELOCATING+ SIZEOF(.data) + ADDR(.data)} :
  { 					
    *(.bss)
    *(COMMON)
    ${RELOCATING+ end = .};
  }
  ${RELOCATING- ${INIT}}
  ${RELOCATING- ${FINI}}
  .stab  0 ${RELOCATING+(NOLOAD)} : 
  {
    [ .stab ]
  }
  .stabstr  0 ${RELOCATING+(NOLOAD)} :
  {
    [ .stabstr ]
  }
}
EOF
