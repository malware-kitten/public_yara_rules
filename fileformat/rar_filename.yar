rule RAR_filename {
  meta:
    author = "Nick Hoffman - Morphick Inc"
    description = "Rule template for finding the filename field within the rar file format"

  strings:
    $header = { 52 61 72 21 }
    $filename = /malicious\.exe/ nocase

  condition:
    (for all of ($header*) : ( $filename in (@+52..@+52+uint16(@+46))))
}
