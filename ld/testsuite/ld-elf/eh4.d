#source: eh4.s
#source: eh4a.s
#ld: -shared
#readelf: -wf
#target: x86_64-*-*

Contents of the .eh_frame section:

00000000 00000014 00000000 CIE
  Version:               1
  Augmentation:          "zR"
  Code alignment factor: 1
  Data alignment factor: -8
  Return address column: 16
  Augmentation data:     1b

  DW_CFA_def_cfa: r7 \(rsp\) ofs 8
  DW_CFA_offset: r16 \(rip\) at cfa-8
  DW_CFA_nop
  DW_CFA_nop

00000018 00000014 0000001c FDE cie=00000000 pc=00000400..00000413
  DW_CFA_set_loc: 00000404
  DW_CFA_def_cfa_offset: 80

00000030 00000014 00000034 FDE cie=00000000 pc=00000413..00000426
  DW_CFA_set_loc: 00000417
  DW_CFA_def_cfa_offset: 80

00000048 ZERO terminator
#pass

