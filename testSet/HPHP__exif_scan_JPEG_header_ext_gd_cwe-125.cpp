static int exif_scan_JPEG_header(image_info_type *ImageInfo) {
  int section, sn;
  int marker = 0, last_marker = M_PSEUDO, comment_correction=1;
  int ll, lh;
  unsigned char *Data;
  size_t fpos, size, got, itemlen;
  jpeg_sof_info  sof_info;

  for(section=0;;section++) {
    // get marker byte, swallowing possible padding
    // some software does not count the length bytes of COM section
    // one company doing so is very much envolved in JPEG...
    // so we accept too
    if (last_marker==M_COM && comment_correction) {
      comment_correction = 2;
    }
    do {
      if ((marker = ImageInfo->infile->getc()) == EOF) {
        raise_warning("File structure corrupted");
        return 0;
      }
      if (last_marker==M_COM && comment_correction>0) {
        if (marker!=0xFF) {
          marker = 0xff;
          comment_correction--;
        } else  {
          last_marker = M_PSEUDO; /* stop skipping 0 for M_COM */
        }
      }
    } while (marker == 0xff);
    if (last_marker==M_COM && !comment_correction) {
      raise_notice("Image has corrupt COM section: some software set "
                   "wrong length information");
    }
    if (last_marker==M_COM && comment_correction)
      return M_EOI; /* ah illegal: char after COM section not 0xFF */

    fpos = ImageInfo->infile->tell();

    if (marker == 0xff) {
      // 0xff is legal padding, but if we get that many, something's wrong.
      raise_warning("To many padding bytes");
      return 0;
    }

    /* Read the length of the section. */

    if ((lh = ImageInfo->infile->getc()) == EOF) {
      raise_warning("File structure corrupted");
      return 0;
    }

    if ((ll = ImageInfo->infile->getc()) == EOF) {
      raise_warning("File structure corrupted");
      return 0;
    }

    itemlen = (lh << 8) | ll;

    if (itemlen < 2) {
      raise_warning("File structure corrupted");
      return 0;
    }

    sn = exif_file_sections_add(ImageInfo, marker, itemlen+1, nullptr);
    if (sn == -1) return 0;
    Data = ImageInfo->file.list[sn].data;

    /* Store first two pre-read bytes. */
    Data[0] = (unsigned char)lh;
    Data[1] = (unsigned char)ll;

    String str = ImageInfo->infile->read(itemlen-2);
    got = str.length();
    if (got != itemlen-2) {
      raise_warning("Error reading from file: "
                      "got=x%04lX(=%lu) != itemlen-2=x%04lX(=%lu)",
                      got, got, itemlen-2, itemlen-2);
      return 0;
    }
    memcpy(Data+2, str.c_str(), got);
    switch(marker) {
      case M_SOS:   /* stop before hitting compressed data  */
        // If reading entire image is requested, read the rest of the data.
        if (ImageInfo->read_all) {
          /* Determine how much file is left. */
          fpos = ImageInfo->infile->tell();
          size = ImageInfo->FileSize - fpos;
          sn = exif_file_sections_add(ImageInfo, M_PSEUDO, size, nullptr);
          if (sn == -1) return 0;
          Data = ImageInfo->file.list[sn].data;
          str = ImageInfo->infile->read(size);
          got = str.length();
          if (got != size) {
            raise_warning("Unexpected end of file reached");
            return 0;
          }
          memcpy(Data, str.c_str(), got);
        }
        return 1;

      case M_EOI:   /* in case it's a tables-only JPEG stream */
        raise_warning("No image in jpeg!");
        return (ImageInfo->sections_found&(~FOUND_COMPUTED)) ? 1 : 0;

      case M_COM: /* Comment section */
        exif_process_COM(ImageInfo, (char *)Data, itemlen);
        break;

      case M_EXIF:
        if (!(ImageInfo->sections_found&FOUND_IFD0)) {
          /*ImageInfo->sections_found |= FOUND_EXIF;*/
          /* Seen files from some 'U-lead' software with Vivitar scanner
             that uses marker 31 later in the file (no clue what for!) */
          exif_process_APP1(ImageInfo, (char *)Data, itemlen, fpos);
        }
        break;

      case M_APP12:
        exif_process_APP12(ImageInfo, (char *)Data, itemlen);
        break;


      case M_SOF0:
      case M_SOF1:
      case M_SOF2:
      case M_SOF3:
      case M_SOF5:
      case M_SOF6:
      case M_SOF7:
      case M_SOF9:
      case M_SOF10:
      case M_SOF11:
      case M_SOF13:
      case M_SOF14:
      case M_SOF15:
        exif_process_SOFn(Data, marker, &sof_info);
        ImageInfo->Width  = sof_info.width;
        ImageInfo->Height = sof_info.height;
        if (sof_info.num_components == 3) {
          ImageInfo->IsColor = 1;
        } else {
          ImageInfo->IsColor = 0;
        }
        break;
      default:
        /* skip any other marker silently. */
        break;
    }

    /* keep track of last marker */
    last_marker = marker;
  }
  return 1;
}