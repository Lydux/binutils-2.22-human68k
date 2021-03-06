/* BFD back-end for Human68k XFile objects.
   Copyright 2011 Free Software Foundation, Inc.
   Written by Lyderic Maillet, <lydux86@gmail.com>

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

/* HLK XFile structure
 * 
 * +---------------------------+
 * |  Header (0x40)            |
 * +---------------------------+
 * |  Text segment             |
 * +---------------------------+
 * |  Data segment             |
 * +---------------------------+
 * |  Relocations fixup table  |
 * +---------------------------+
 * |  Symbols table            |
 * +---------------------------+ 
 * |  Debug informations       |
 * +---------------------------+ 
 */


#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"

#define PUT_MAGIC   H_PUT_16
#define GET_MAGIC   H_GET_16

#define PUT_LONG    H_PUT_32
#define PUT_SHORT   H_PUT_16
#define PUT_BYTE    H_PUT_8
#define GET_LONG    H_GET_32
#define GET_SHORT   H_GET_16
#define GET_BYTE    H_GET_8

struct xfile_internal_exec
{
  unsigned short magic;
  unsigned char reserved1;
  unsigned char loadmode;
  bfd_vma base;
  bfd_vma entry;
  bfd_size_type text_size;
  bfd_size_type data_size;
  bfd_size_type bss_size;
  bfd_size_type rel_size;
  bfd_size_type syms_size;
  bfd_size_type scdl;
  bfd_size_type scdi;
  bfd_size_type scdn;
  unsigned long reserved[5];
};

typedef struct xfile_data_struct
{
  struct xfile_internal_exec exec;

  asection *textsec;
  asection *datasec;
  asection *bsssec;

  asymbol *symbols;
  char *strtab;
  int strtabsize;

  unsigned long *fixuptab;
  int fixupcount;

  file_ptr treloff;
  bfd_size_type trelsz;
  file_ptr dreloff;
  bfd_size_type drelsz;
}
tdata_type;

#define XDATA(abfd) (abfd->tdata.xfile_data)

struct xext_hdr
{
  unsigned char magic[2];         /* Magic number = "HU". */
  unsigned char reserved1[1];
  unsigned char loadmode[1];
  unsigned char base[4];          /* Load address */
  unsigned char entry[4];         /* Start address.  */
  unsigned char text_size[4];     /* Length of text section in bytes. */
  unsigned char data_size[4];     /* Length of data section in bytes. */
  unsigned char bss_size[4];      /* Length of bss area in bytes.  */
  unsigned char rel_size[4];      /* Length of relocation table.  */
  unsigned char syms_size[4];     /* Length of symbol table in bytes. */
  unsigned char scdl[4];          /* Debug line number table size */
  unsigned char scdi[4];          /* Debug information size */
  unsigned char scdn[4];          /* Debug name table size */
  unsigned char reserved[4*5];    /* Not used (Sometimes the last 
                                   * elements contains the file size) */
};

/* Header constants.  */
#define X_MAGIC     0x4855        /* 'HU' */

struct xsyment {
  unsigned char s_location;	/* 0x00 = External 0x02 = Local */
  unsigned char s_section;	/* 0x01 = TEXT 0x02 = DATA 0x03 = BSS */
  unsigned char s_value[4];	/* Symbol absolute position in code.  */
};

/* XSyment s_sections.  */
#define N_TEXT  0x01
#define N_DATA  0x02
#define N_BSS   0x03
#define N_STACK 0x04

/* Sections helpers.  */
#define xfile_section_is_text(section) (section->flags & SEC_CODE)
#define xfile_section_is_data(section) (section->flags & SEC_DATA)
#define xfile_section_is_bss(section) (section->flags == SEC_ALLOC)
#define xfile_section_is_stack(section) \
  (strcmp (bfd_section_name (abfd, section), ".stack") == 0)

#define xfile_textsec(abfd) (XDATA(abfd)->textsec)
#define xfile_datasec(abfd) (XDATA(abfd)->datasec)
#define xfile_bsssec(abfd) (XDATA(abfd)->bsssec)

/* XSyment s_location.  */
#define S_SYM_EXTERNAL  0x00
#define S_SYM_LOCAL     0x02

/* Relocations */
#define X_LONG_RELFIXUP(r) (r & 1)

/* Header helpers. */
#define X_EXECSZ	(sizeof (struct xext_hdr))
#define X_TXTOFF(execp)	(X_EXECSZ)
#define X_DATOFF(execp) (X_TXTOFF(execp) + execp->text_size)
#define X_RELOFF(execp) (X_DATOFF(execp) + execp->data_size)
#define X_SYMOFF(execp) (X_RELOFF(execp) + execp->rel_size)
#define X_SCDOFF(execp) (X_SYMOFF(execp) + execp->syms_size)

/* XFile align all strings in a 2 bytes boundary (padded with zero) */
#define STRALIGN(s) ((strlen (s) + 2) & ~1)

static int xfile_count_section_fixup (bfd *abfd, asection *s);
static bfd_boolean xfile_slurp_fixup_table (bfd *abfd);

/* XFile only perform absolute 32 bits relocation */

static reloc_howto_type xfile_howto_table[] =
{
/* Type   rs size bsz  pcrel bitpos ovrf                  sf name     part_inpl readmask  setmask    pcdone */
HOWTO( 0, 0,  4,   32, FALSE, 0, complain_overflow_dont, 0, "R_68K_32", TRUE, 0xffffffff, 0xffffffff, FALSE),
};

/* Swap external to internal header.  */

static void
xfile_swap_exec_header_in (bfd *abfd,
                          struct xfile_internal_exec *execp,
                          struct xext_hdr *bytes)
{
  execp->magic      = GET_MAGIC (abfd, bytes->magic);

  execp->reserved1  = GET_BYTE (abfd, bytes->reserved1);
  execp->loadmode   = GET_BYTE (abfd, bytes->loadmode);

  execp->base       = GET_LONG (abfd, bytes->base);
  execp->entry      = GET_LONG (abfd, bytes->entry);
  execp->text_size  = GET_LONG (abfd, bytes->text_size);
  execp->data_size  = GET_LONG (abfd, bytes->data_size);
  execp->bss_size   = GET_LONG (abfd, bytes->bss_size);
  execp->rel_size   = GET_LONG (abfd, bytes->rel_size);
  execp->syms_size  = GET_LONG (abfd, bytes->syms_size);

  execp->scdl       = GET_LONG (abfd, bytes->scdl);
  execp->scdi       = GET_LONG (abfd, bytes->scdi);
  execp->scdn       = GET_LONG (abfd, bytes->scdn);

  execp->reserved[0]  = GET_LONG (abfd, bytes->reserved);
  execp->reserved[1]  = GET_LONG (abfd, bytes->reserved + 4);
  execp->reserved[2]  = GET_LONG (abfd, bytes->reserved + 8);
  execp->reserved[3]  = GET_LONG (abfd, bytes->reserved + 12);
  execp->reserved[4]  = GET_LONG (abfd, bytes->reserved + 16);
}

/* Swap internal header to external in the correct byte order.  */

static void
xfile_swap_exec_header_out (bfd *abfd,
                            struct xfile_internal_exec *execp,
                            struct xext_hdr *bytes)
{
  PUT_MAGIC (abfd, execp->magic,      bytes->magic);

  PUT_BYTE (abfd, execp->reserved1,   bytes->reserved1);
  PUT_BYTE (abfd, execp->loadmode,    bytes->loadmode);

  PUT_LONG (abfd, execp->base,        bytes->base);
  PUT_LONG (abfd, execp->entry,       bytes->entry);
  PUT_LONG (abfd, execp->text_size,   bytes->text_size);
  PUT_LONG (abfd, execp->data_size,   bytes->data_size);
  PUT_LONG (abfd, execp->bss_size,    bytes->bss_size);
  PUT_LONG (abfd, execp->rel_size,    bytes->rel_size);
  PUT_LONG (abfd, execp->syms_size,   bytes->syms_size);

  PUT_LONG (abfd, execp->scdl,        bytes->scdl);
  PUT_LONG (abfd, execp->scdi,        bytes->scdi);
  PUT_LONG (abfd, execp->scdn,        bytes->scdn);

  PUT_LONG (abfd, execp->reserved[0], bytes->reserved);
  PUT_LONG (abfd, execp->reserved[1], bytes->reserved + 4);
  PUT_LONG (abfd, execp->reserved[2], bytes->reserved + 8);
  PUT_LONG (abfd, execp->reserved[3], bytes->reserved + 12);
  PUT_LONG (abfd, execp->reserved[4], bytes->reserved + 16);
}

/* Make all sections needed by xfile */

static bfd_boolean
xfile_make_sections (bfd *abfd)
{
  tdata_type *data = XDATA (abfd);
  struct xfile_internal_exec *execp = &XDATA (abfd)->exec;
  bfd_vma lma = execp->base;
  asection *s;
  int count;

  if (execp->text_size > 0 && xfile_textsec (abfd) == NULL)
  {
    if ((xfile_textsec (abfd) = bfd_make_section (abfd, ".text")) == NULL)
      return FALSE;

    s = xfile_textsec (abfd);

    s->size = execp->text_size;
    s->filepos = X_TXTOFF (execp);
    s->lma = s->vma = lma;
    s->flags = SEC_HAS_CONTENTS | SEC_ALLOC | SEC_LOAD | SEC_READONLY |
               SEC_CODE;
    s->alignment_power = 2;

    count = xfile_count_section_fixup (abfd, s);
    if (count > 0)
    {
      s->reloc_count = count;
      s->flags |= SEC_RELOC;
    }

    lma += execp->text_size;
  }

  if (execp->data_size > 0 && xfile_datasec (abfd) == NULL)
  {
    if ((xfile_datasec (abfd) = bfd_make_section (abfd, ".data")) == NULL)
      return FALSE;

    s = xfile_datasec (abfd);

    s->size = execp->data_size;
    s->filepos = X_DATOFF (execp);
    s->lma = s->vma = lma;
    s->flags = SEC_HAS_CONTENTS | SEC_ALLOC | SEC_LOAD | SEC_DATA;
    s->alignment_power = 1;

    count = xfile_count_section_fixup (abfd, s);
    if (count > 0)
    {
      s->reloc_count = count;
      s->flags |= SEC_RELOC;
    }
    
    lma += execp->data_size;
  }

  if (execp->bss_size > 0 && xfile_bsssec (abfd) == NULL)
  {
    if ((data->bsssec = bfd_make_section (abfd, ".bss")) == NULL)
      return FALSE;

    s = xfile_bsssec (abfd);

    s->size = execp->bss_size;
    s->lma = s->vma = lma;
    s->flags = SEC_ALLOC;
    s->alignment_power = 1;
  }

  return TRUE;
}

/* Set up the tdata informations.  */

static bfd_boolean
xfile_mkobject (bfd *abfd)
{
  if (abfd->tdata.xfile_data == NULL)
  {
    bfd_size_type amt = sizeof (tdata_type);
    tdata_type *tdata = bfd_alloc (abfd, amt);

    if (tdata == NULL)
      return FALSE;

    XDATA (abfd) = tdata;
  }

  bfd_default_set_arch_mach (abfd, bfd_arch_m68k, 0);

  return TRUE;
}

/*
 * Check whether an existing file is an xfile object.
 */

static const bfd_target *
xfile_object_p (bfd *abfd)
{
  struct xext_hdr bytes;
  struct xfile_internal_exec *execp;
  bfd_size_type amt;
  struct stat statbuf;
  
  if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0)
    return NULL;

  amt = sizeof (struct xext_hdr);
  if (bfd_bread (&bytes, amt, abfd) != amt)
  {
    if (bfd_get_error () != bfd_error_system_call)
      bfd_set_error (bfd_error_wrong_format);
    return NULL;
  }

  xfile_mkobject (abfd);

  execp = &XDATA(abfd)->exec;
  xfile_swap_exec_header_in (abfd, execp, &bytes);

  /* Magic must be "HU" */
  if (execp->magic != X_MAGIC)
  {
    bfd_set_error (bfd_error_wrong_format);
    return NULL;
  }

  /* Some more validations : sum of each block size must be
   * equal to file size.
   * FIXME : SCD isn't the last block. Find a way to generate those */
  amt = X_SCDOFF (execp);
  
  if (bfd_stat (abfd, &statbuf) < 0)
  {
    bfd_set_error (bfd_error_system_call);
    return NULL;
  }

  if ( (off_t) amt != statbuf.st_size)
  {
    bfd_set_error (bfd_error_file_truncated);
    return NULL;
  }

  /* Relocation fixups are needed for section flags */
  xfile_slurp_fixup_table (abfd);

  xfile_make_sections (abfd);

  /* Fill flags */
  abfd->flags = EXEC_P;

  if (execp->syms_size > 0)
    abfd->flags |= HAS_SYMS;
 
  if (XDATA (abfd)->fixupcount > 0)
    abfd->flags |= HAS_RELOC;

  bfd_get_start_address (abfd) = execp->entry - execp->base;

  return abfd->xvec;
}

/*
 * Get contents of one section.
 */

static bfd_boolean
xfile_get_section_contents (bfd *abfd,
                            asection *section,
                            void * location,
                            file_ptr offset,
                            bfd_size_type count)
{
  if (count == 0 || ((section->flags & SEC_HAS_CONTENTS) == 0))
    return TRUE;

  if ((bfd_size_type) (offset+count) > section->size ||
       bfd_seek (abfd, (file_ptr) (section->filepos + offset), SEEK_SET) != 0 ||
       bfd_bread (location, count, abfd) != count)
    return FALSE;

  return TRUE;
}

/* Count the number of symbol in file.
 * We just loop inside the sym block, looking for each symbol name
 * end. There is no other way.
 */

static bfd_boolean
xfile_slurp_symbol_table (bfd *abfd ATTRIBUTE_UNUSED)
{
  tdata_type *data = XDATA (abfd);
  struct xfile_internal_exec *execp = &data->exec;
  bfd_size_type amt;
  unsigned char *xsymcache;
  asymbol *syment;
  struct xsyment *xsymptr;
  char *xsymname, *strptr;
  int symcount, strtabsize;

  if (data->symbols != NULL)
    return TRUE;

  /* Cache symbols block */
  amt = execp->syms_size;

  xsymcache = bfd_alloc (abfd, amt);

  if ((bfd_seek (abfd, (file_ptr) X_SYMOFF (execp), SEEK_SET) !=0) ||
      (bfd_bread (xsymcache, amt, abfd) != amt))
  {
    bfd_set_error (bfd_error_system_call);
    return FALSE;
  }

  /* Count all symbols we have as well as the amount of bytes needed
   * to store symbols names  */
  xsymptr = (struct xsyment *) xsymcache;
  symcount = 0;
  strtabsize = 0;
  while (xsymptr < (struct xsyment *) (xsymcache + amt))
  {
    /* Validate symbol entry */
    if (xsymptr->s_location != S_SYM_EXTERNAL &&
        xsymptr->s_location != S_SYM_LOCAL)
      return FALSE;

    xsymname = (char *) (xsymptr + 1);
    strtabsize += strlen (xsymname) + 1;
    /* Strings are 16 bits aligned  */
    xsymptr = (struct xsyment *) (xsymname + STRALIGN (xsymname));

    symcount ++;
  }

  bfd_get_symcount (abfd) = symcount;
  data->strtabsize = strtabsize;

  if (symcount == 0)
    return TRUE;

  amt = symcount * sizeof (asymbol);
  data->symbols = bfd_alloc (abfd, amt);

  amt = data->strtabsize;
  data->strtab = bfd_zalloc (abfd, amt);

  xsymptr = (struct xsyment *) xsymcache;
  xsymname = data->strtab;
  for (syment = data->symbols;
       symcount;
       syment++, symcount--)
  {
    strptr = (char *) (xsymptr + 1);

    if (xsymptr->s_location == S_SYM_LOCAL)
    {
      switch (xsymptr->s_section)
      {
        case N_TEXT:
	  syment->section = xfile_textsec (abfd); break;
	case N_DATA:
	  syment->section = xfile_datasec (abfd); break;
	case N_BSS:
	  syment->section = xfile_bsssec (abfd); break;
	default:
	  /* FIXME : Maybe created with hlk060, or SX XFile */
          syment->section = bfd_abs_section_ptr;
      }
    }
    else
      /* External symbol */
      syment->section = bfd_com_section_ptr;

    syment->the_bfd = abfd;
    syment->value = GET_LONG (abfd, xsymptr->s_value) - syment->section->lma;
    syment->name = strcat (xsymname, strptr);
    xsymname += strlen (strptr) + 1;

    xsymptr = (struct xsyment *) (strptr + STRALIGN (strptr));
  }

  return TRUE;
}

/*
 * Return the amount of memory needed to read the symbol table.  
 */

static long
xfile_get_symtab_upper_bound (bfd *abfd)
{
  if (!xfile_slurp_symbol_table (abfd))
    return -1;

  return (bfd_get_symcount (abfd) + 1) * sizeof (asymbol *);
}

/* 
 * Return the symbol table.
 */

static long
xfile_canonicalize_symtab (bfd *abfd,
          asymbol **alocation)
{
  unsigned int i, symcount;
  asymbol *s;

  if (!xfile_slurp_symbol_table (abfd))
    return -1;

  symcount = bfd_get_symcount (abfd);

  for (i = 0, s = XDATA (abfd)->symbols; 
       i < symcount; 
       s++, i++)
    *alocation++ = s;

  *alocation = NULL;

  return symcount;
}

/* 
 * Swap external to internal reloc fixup
 */

static unsigned long
xfile_swap_fixup (bfd *abfd, unsigned short **fixup)
{
  unsigned long rel;

  rel = GET_SHORT (abfd, *fixup);
  (*fixup)++;

  if (X_LONG_RELFIXUP (rel))
  {
    rel <<= 16;
    rel |= GET_SHORT (abfd, *fixup);
    (*fixup)++;
  }

  return rel;
}

/*
 * Slurp the relocation fixup table
 */

static bfd_boolean
xfile_slurp_fixup_table (bfd *abfd)
{
  tdata_type *data = XDATA (abfd);
  struct xfile_internal_exec *execp = &data->exec;
  unsigned short *fixupcache, *fixupend, *pfixup;
  bfd_size_type i, amt, count;
  bfd_vma base;
  
  amt = execp->rel_size;

  if (amt == 0)
    return TRUE;

  fixupcache = bfd_malloc (amt);
  fixupend = &fixupcache[amt / sizeof (unsigned short)];

  if ((bfd_seek (abfd, (file_ptr) X_RELOFF (execp), SEEK_SET) != 0) ||
      (bfd_bread (fixupcache, amt, abfd) != amt))
  {
     free (fixupcache);
     return FALSE;
  }

  /* Count fixup table */
  count = 0;
  pfixup = fixupcache;
  while (pfixup < fixupend)
  {
    if (xfile_swap_fixup (abfd, &pfixup) == 0)
    {
      free (fixupcache);
      return FALSE;
    }
    count++;
  }

  /* Build table */
  data->fixupcount = count;
  amt = count * sizeof (bfd_vma);

  data->fixuptab = bfd_alloc (abfd, amt);

  base = 0;
  pfixup = fixupcache;
  for (i = 0; i < count; i++)
  {
    base += xfile_swap_fixup (abfd, &pfixup);

    data->fixuptab[i] = base;
  }
 
  free (fixupcache);

  return TRUE;
}

static bfd_boolean
xfile_build_reloc_table (bfd *abfd, sec_ptr asect, asymbol **symbols ATTRIBUTE_UNUSED)
{
  tdata_type *data = XDATA (abfd);
  struct xfile_internal_exec *execp = &data->exec;
  int i, count;
  arelent *reloc_cache;
  unsigned long *fixp;
  arelent *rptr;

  count = asect->reloc_count;

  if (count == 0)
    return TRUE;

  reloc_cache = bfd_zmalloc (count * sizeof (arelent));
  if (reloc_cache == NULL)
    return FALSE;

  /* Find the first entry for this section in fixup table */
  fixp = data->fixuptab;
  while (*fixp < asect->lma - execp->base)
    fixp++;

  for (i = 0, rptr = reloc_cache;
       i < count; 
       i++, rptr++, fixp++)
  {
     rptr->address = (bfd_size_type) *fixp - (asect->lma - execp->base);
     rptr->addend = 0;
     rptr->howto = &xfile_howto_table[0];
     /* TODO : 
      * To lookup for a symbol, we need to read the value pointed at 
      * rptr->address within section image. Then lookup this value
      * in symbol list.
      */
     rptr->sym_ptr_ptr = &asect->symbol;
  }

  asect->relocation = reloc_cache;

  return TRUE;
}

static int
xfile_count_section_fixup (bfd *abfd, asection *s)
{
  tdata_type *data = XDATA (abfd);
  struct xfile_internal_exec *execp = &data->exec;
  int count;
  unsigned long *p;
  bfd_vma base = execp->base;

  if (data->fixuptab == NULL)
    xfile_slurp_fixup_table (abfd);

  if (data->fixupcount == 0)
    return 0;

  p = data->fixuptab;
  while (*p + base < s->lma)
    p++;

  count = 0;
  while ((count < data->fixupcount) && 
         (*p + base < s->lma + s->size))
  {
    count++;
    p++;
  }

  return count;
}

/*
 * Return the amount of memory needed to read the fixup reloc table.
 */

static long
xfile_get_reloc_upper_bound (bfd *abfd ATTRIBUTE_UNUSED, 
                             sec_ptr asect)
{
  return (asect->reloc_count + 1) * sizeof (arelent *);
}

/* TODO:
 * Return the relocation table.
 */

static long
xfile_canonicalize_reloc (bfd *abfd,
          sec_ptr section,
          arelent **relptr,
          asymbol **symbols)
{
  arelent *tblptr;
  bfd_size_type count;

  if (section == xfile_bsssec (abfd))
  {
    *relptr = NULL;
    return 0;
  }

  if (!xfile_build_reloc_table (abfd, section, symbols))
    return FALSE;

  tblptr = section->relocation;

  for (count = 0; count < section->reloc_count; count++)
  {
    *relptr++ = tblptr++;
  }

  *relptr = NULL;

  return section->reloc_count;
}

/* TODO:
 * Get information about a symbol.
 */

static void
xfile_get_symbol_info (bfd *abfd ATTRIBUTE_UNUSED,
          asymbol *symbol,
          symbol_info *ret)
{
  bfd_symbol_info (symbol, ret);
}

static void
xfile_print_symbol (bfd *abfd, 
          void *afile, 
	  asymbol *symbol,
	  bfd_print_symbol_type how)
{
  FILE *file = (FILE *) afile;

  switch (how)
  {
    case bfd_print_symbol_name:
    case bfd_print_symbol_more:
      fprintf (file, "%s", symbol->name);
      break;
    case bfd_print_symbol_all:
        bfd_print_symbol_vandf (abfd, (void *) file, symbol);
	
        fprintf (file, " %-5s %s", symbol->section->name, symbol->name);
	break;
  }
}

/* Fill exec header */

static bfd_boolean
xfile_prep_exec (bfd *abfd)
{
  struct xfile_internal_exec *execp;
  asection *section;
  
  execp = &XDATA (abfd)->exec;
  
  execp->magic = X_MAGIC;
  execp->base = 0;
  execp->entry = bfd_get_start_address (abfd);

  /* Find sections text, data and bss size.  */
  for (section = abfd->sections; 
       section != NULL; 
       section = section->next)
  {
    if (xfile_section_is_text (section))
    {
      /* Text section lma will be the first loaded segment.
       * Set its lma to base of loading address. */
      execp->base = section->lma;
      execp->text_size += section->size;
    }
    else if (xfile_section_is_data (section))
      execp->data_size += section->size;
    else if (xfile_section_is_bss (section))
      execp->bss_size += section->size;
    else
      return FALSE;
  }

  return TRUE;
}

/* Write exec header.  */

static bfd_boolean
xfile_write_head (bfd *abfd)
{
  struct xfile_internal_exec *execp;
  struct xext_hdr bytes;

  execp = &XDATA (abfd)->exec;
  xfile_swap_exec_header_out (abfd, execp, &bytes);

  if ((bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0) ||
      (bfd_bwrite (&bytes, sizeof (struct xext_hdr), abfd) != sizeof (struct xext_hdr)))
    return FALSE;

  return TRUE;
}

static int
comp (const void * ap, const void * bp)
{
  arelent *a = *((arelent **) ap);
  arelent *b = *((arelent **) bp);

  return a->address - b->address;
}

/* Calculate and write all relocations.  */

/* About Human68k relocations table :
 * Relocations entries are simple a set of fixups of only 16 or 
 * 32 bits words which tell the offset position of code to 
 * relocate into Text+Data segments. 
 * All positions are relative to the previous one, starting 
 * from 0 (Top of Text segment).
 * The 16 bits MSB on a 32bits readed word specify the relocation size :
 * short (odd) or long (even).
 * All relocatable code should be based on the load address specified
 * in XFile header.
 */

static bfd_boolean
xfile_write_relocs (bfd *abfd)
{
  asection *s;
  arelent *reloc;
  asymbol *sym;
  bfd_vma last_offset = 0, base = 0, offset, delta;
  int relsec_size = 0;
  unsigned i;
  unsigned char d[4];
  
  for (s = abfd->sections; s != NULL; s = s->next)
  {
    if (s->reloc_count != 0)
      /* Relocations need to be sorted ascending.  */
      qsort (s->orelocation, s->reloc_count, sizeof (arelent **), comp);
  }
  
  for (s = abfd->sections; s != NULL; s = s->next)
  {
    /* text and data only.  */
    if ((s->flags & (SEC_LOAD | SEC_ALLOC)) == 0)
      continue;
      
    for (i = 0; i < s->reloc_count; i++)
    {
      reloc = s->orelocation[i];
      
      /* Keep only absolute relocation.  */
      if (reloc->howto->type != 1)
        continue;
      
      /* Discard relocations over absolute symbol. */
      if (reloc->sym_ptr_ptr)
      {
        sym = (asymbol *) *reloc->sym_ptr_ptr;
        
        if (sym->section == bfd_abs_section_ptr)
          continue;
	  }

      /* Absolute offset in image.  */
      offset = reloc->address + base;
      /* Relative offset from the last one.  */
      delta = offset - last_offset;
      
      if (delta & 0x10000)
      {
        /* Honour Human68k long relocations.  */
        PUT_LONG (abfd, delta, d);
        if (bfd_bwrite (&d, 4, abfd) != 4)
          return FALSE;
        relsec_size += 4;
      }
      else
      {
        /* Short reloc */
        PUT_SHORT (abfd, delta, d);
        if (bfd_bwrite (&d, 2, abfd) != 2)
          return FALSE;
        relsec_size += 2;
      }

      last_offset = offset;
    }

    base = s->size;
  }
  
  struct xfile_internal_exec *execp = &XDATA (abfd)->exec;
  execp->rel_size = relsec_size;
  
  return TRUE;
}

/* Write symbols.  */

static bfd_boolean
xfile_write_symbols (bfd *abfd)
{
  unsigned int count;
  asymbol *sym, **generic = bfd_get_outsymbols (abfd);
  asection *section;
  bfd_size_type amt;
  int syms_size = 0;

  for (count = 0; count < bfd_get_symcount (abfd); count++)
  {
    sym = generic[count];

    /* Debug syms & section not supported yet.  */
    if (sym->flags & (BSF_FILE | BSF_SECTION_SYM))
      continue;
    
    section = sym->section;

    if ((section->flags & (SEC_LOAD | SEC_ALLOC)) == 0)
      continue;

    struct xsyment xsym;
    
    xsym.s_location = S_SYM_LOCAL;

    if (bfd_is_com_section (section))
    {
      /* Special case */
      xsym.s_location = S_SYM_EXTERNAL;
      xsym.s_section = 0x03;
    }
    
    if (xfile_section_is_text (section))
      xsym.s_section = N_TEXT;
    else if (xfile_section_is_data (section))
      xsym.s_section = N_DATA;
    else if (xfile_section_is_bss (section))
      xsym.s_section = N_BSS;
    else if (xfile_section_is_stack (section))
      xsym.s_section = N_STACK;
    else
      /* Don't know what to do.  */
      return FALSE;

    PUT_LONG (abfd, sym->value + section->lma, xsym.s_value);
    
    /* Write symbol infos.  */
    amt = sizeof (struct xsyment);
    if (bfd_bwrite (&xsym, amt, abfd) != amt)
      return FALSE;
      
    syms_size += amt;
      
    /* Write symbol name.  */
    amt = strlen (sym->name);
    if (bfd_bwrite (sym->name, amt, abfd) != amt)
      return FALSE;
      
    syms_size += amt;

    amt = (2 - (amt & 1)); /* Honour 16 bits aligned string.  */
    if (bfd_bwrite ("\0\0", amt, abfd) != amt)
      return FALSE;
    
    syms_size += amt;
  }

  struct xfile_internal_exec *execp = &XDATA (abfd)->exec;
  execp->syms_size = syms_size;

  return TRUE;
}

/* Sections contents should have been written.
 * Process to relocations and symbols */

static bfd_boolean
xfile_write_object_contents (bfd *abfd)
{
  if (abfd->flags & EXEC_P)
  {    
    if (!abfd->output_has_begun)
    {
      xfile_prep_exec (abfd);
      abfd->output_has_begun = TRUE;
    }
  }
  else
  {
    /* TODO : if someone wants to add generation of HLK compatible 
     * objects, implement it here. Until then, only support for high-end
     * XFile conversion via objcopy. */
    (*_bfd_error_handler) (_("Non executable object not supported yet"));
    bfd_set_error (bfd_error_wrong_format);
    return FALSE;
  }

  return  xfile_write_relocs (abfd) &&
          xfile_write_symbols (abfd) &&
          xfile_write_head (abfd);
}

/* Write section content.  */

static bfd_boolean
xfile_set_section_contents (bfd *abfd,
			     asection *section,
			     const void *data,
			     file_ptr offset,
			     bfd_size_type size)
{
  if (! abfd->output_has_begun)
  {
    xfile_prep_exec (abfd);
    
    bfd_boolean found_low;
    bfd_vma low;
    asection *s;

    /* The lowest section LMA sets the virtual address of the start
       of the file.  We use this to set the file position of all the
       sections.  */
    found_low = FALSE;
    low = 0;
    for (s = abfd->sections; s != NULL; s = s->next)
    {
      if (((s->flags
        & (SEC_HAS_CONTENTS | SEC_LOAD | SEC_ALLOC | SEC_NEVER_LOAD))
        == (SEC_HAS_CONTENTS | SEC_LOAD | SEC_ALLOC))
        && (s->size > 0)
        && (! found_low || s->lma < low))
      {
        low = s->lma;
        found_low = TRUE;
      }
    }

    for (s = abfd->sections; s != NULL; s = s->next)
    {
      s->filepos = s->lma - low + sizeof (struct xext_hdr);

      /* Skip following warning check for sections that will not
         occupy file space.  */
      if ((s->flags
           & (SEC_HAS_CONTENTS | SEC_ALLOC | SEC_NEVER_LOAD))
          != (SEC_HAS_CONTENTS | SEC_ALLOC)
          || (s->size == 0))
        continue;

      /* If attempting to generate a binary file from a bfd with
         LMA's all over the place, huge (sparse?) binary files may
         result.  This condition attempts to detect this situation
         and print a warning.  Better heuristics would be nice to
         have.  */

      if (s->filepos < 0)
        (*_bfd_error_handler)
          (_("Warning: Writing section `%s' to huge (ie negative) file offset 0x%lx."),
           bfd_get_section_name (abfd, s),
           (unsigned long) s->filepos);
    }

    abfd->output_has_begun = TRUE;
  }

  /* Only text, data and bss are interesting */
  if ((section->flags & (SEC_LOAD | SEC_ALLOC)) == 0)
    return TRUE;

  return _bfd_generic_set_section_contents (abfd, section, data, offset, size);
}

/* Return the size of exec header. */

static int
xfile_sizeof_headers (bfd *abfd ATTRIBUTE_UNUSED,
                       struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  return sizeof (struct xext_hdr);
}

#define xfile_close_and_cleanup           _bfd_generic_close_and_cleanup
#define xfile_bfd_free_cached_info        _bfd_generic_bfd_free_cached_info
#define xfile_new_section_hook            _bfd_generic_new_section_hook
#define xfile_set_arch_mach               bfd_default_set_arch_mach
#define xfile_get_section_contents_in_window  \
    _bfd_generic_get_section_contents_in_window
#define xfile_make_empty_symbol           _bfd_generic_make_empty_symbol
#define xfile_bfd_is_local_label_name     bfd_generic_is_local_label_name
#define xfile_bfd_is_target_special_symbol  \
    ((bfd_boolean (*) (bfd *, asymbol *)) bfd_false)
#define xfile_get_lineno                  _bfd_nosymbols_get_lineno
#define xfile_find_nearest_line           _bfd_nosymbols_find_nearest_line
#define xfile_find_inliner_info           _bfd_nosymbols_find_inliner_info
#define xfile_bfd_make_debug_symbol       _bfd_nosymbols_bfd_make_debug_symbol
#define xfile_read_minisymbols            _bfd_generic_read_minisymbols
#define xfile_minisymbol_to_symbol        _bfd_generic_minisymbol_to_symbol
#define xfile_bfd_reloc_type_lookup       _bfd_norelocs_bfd_reloc_type_lookup
#define xfile_bfd_reloc_name_lookup       _bfd_norelocs_bfd_reloc_name_lookup
#define xfile_bfd_get_relocated_section_contents  \
    bfd_generic_get_relocated_section_contents
#define xfile_bfd_relax_section           bfd_generic_relax_section
#define xfile_bfd_link_hash_table_create  _bfd_generic_link_hash_table_create
#define xfile_bfd_link_hash_table_free    _bfd_generic_link_hash_table_free
#define xfile_bfd_link_add_symbols        _bfd_generic_link_add_symbols
#define xfile_bfd_link_just_syms          _bfd_generic_link_just_syms
#define xfile_bfd_copy_link_hash_symbol_type \
    _bfd_generic_copy_link_hash_symbol_type
#define xfile_bfd_final_link              _bfd_generic_final_link
#define xfile_bfd_link_split_section      _bfd_generic_link_split_section
#define xfile_bfd_gc_sections             bfd_generic_gc_sections
#define xfile_bfd_lookup_section_flags    bfd_generic_lookup_section_flags
#define xfile_bfd_merge_sections          bfd_generic_merge_sections
#define xfile_bfd_is_group_section        bfd_generic_is_group_section
#define xfile_bfd_discard_group           bfd_generic_discard_group
#define xfile_section_already_linked      _bfd_generic_section_already_linked
#define xfile_bfd_define_common_symbol    bfd_generic_define_common_symbol

const bfd_target xfile_vec =
{
  "xfile",			/* name */
  bfd_target_xfile_flavour,	/* flavour */
  BFD_ENDIAN_BIG,		/* byteorder */
  BFD_ENDIAN_BIG,		/* header_byteorder */
  (HAS_RELOC | EXEC_P | WP_TEXT),			/* object_flags */
  (SEC_ALLOC | SEC_LOAD | SEC_READONLY | SEC_CODE | SEC_DATA
   | SEC_RELOC | SEC_HAS_CONTENTS), /* section_flags */
  0,				/* symbol_leading_char */
  ' ',				/* ar_pad_char */
  16,				/* ar_max_namelen */
  0,				/* match priority.  */
  bfd_getb64, bfd_getb_signed_64, bfd_putb64,
  bfd_getb32, bfd_getb_signed_32, bfd_putb32,
  bfd_getb16, bfd_getb_signed_16, bfd_putb16,	/* data */
  bfd_getb64, bfd_getb_signed_64, bfd_putb64,
  bfd_getb32, bfd_getb_signed_32, bfd_putb32,
  bfd_getb16, bfd_getb_signed_16, bfd_putb16,	/* hdrs */
  {				/* bfd_check_format */
    _bfd_dummy_target,
    xfile_object_p,
    _bfd_dummy_target,
    _bfd_dummy_target,
  },
  {				/* bfd_set_format */
    bfd_false,
    xfile_mkobject,
    bfd_false,
    bfd_false,
  },
  {				/* bfd_write_contents */
    bfd_false,
    xfile_write_object_contents,
    bfd_false,
    bfd_false,
  },

  BFD_JUMP_TABLE_GENERIC (xfile),
  BFD_JUMP_TABLE_COPY (_bfd_generic),
  BFD_JUMP_TABLE_CORE (_bfd_nocore),
  BFD_JUMP_TABLE_ARCHIVE (_bfd_noarchive),
  BFD_JUMP_TABLE_SYMBOLS (xfile),
  BFD_JUMP_TABLE_RELOCS (xfile),
  BFD_JUMP_TABLE_WRITE (xfile),
  BFD_JUMP_TABLE_LINK (xfile),
  BFD_JUMP_TABLE_DYNAMIC (_bfd_nodynamic),

  NULL,

  NULL
};
