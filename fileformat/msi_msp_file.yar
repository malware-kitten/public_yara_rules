private rule MSI_MSP_File {
  meta:
    description = "rule to ID MSI or MSP files GUID's Borrowed from https://opensource.apple.com/source/file/file-54/file/src/readcdf.c "
    author = "Nick Hoffman - Morphick Inc."

  strings:
    //header of the ole compound format
    $header_compound = { d0 cf 11 e0 a1 b1 1a e1 }
    //root entry property which would contain a substream with the guid for an MSI file, typically this will exist at 0x400, but may exist elsewhere so it's best to look for the relative offset and scan from there
    $root_entry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    //guid a and b for the MSI format should exist at offset $root_entry + 0x50
    $msi_guid_a = { 84 10 0c 00 00 00 00 00 }
    $msi_guid_b = { c0 00 00 00 00 00 00 46 }

    //\x86\x10\x0c\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46
    $msp_guid_a = { 86 10 0c 00 00 00 00 00}
    $msp_guid_b = { c0 00 00 00 00 00 00 46}

  condition:
    $header_compound at 0 and
    for all of ($root_entry*) :
       ( ($msi_guid_a at @+0x50 and
         $msi_guid_b at @+0x50+8) or
     ($msp_guid_a at @+0x50 and
          $msp_guid_b at @+0x50+8)
       )
}
