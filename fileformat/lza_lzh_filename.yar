rule lza_filename {
  meta:
    author = "Nick Hoffman - Morphick Inc"
    description = "Rule template for finding the filename field within the LZA or LZH file format"

  strings:
    $header = { 2d 6c (7a|68) ?? 2d } // -lh or -lz
    $filename = /malicious\.exe/ nocase
    
  condition:
    $header at 2 and
    $filename in (26..26+uint8(25))
}
