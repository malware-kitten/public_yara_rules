/*
According to the ACE specification a filename of a filecontained within an ACE
file is stored at header +88 (-7 due to the header offset) and the length is 
the uint16 at offset 86 (-7 again for the header offset)

Full spec for ACE headers can be found here -> https://notendur.hi.is/~hjj1/technote.doc

Swap out the dummy filename "malicious.exe" with a filename, extension or regex

*/

rule ace_filename {

  meta:
    author = "Nick Hoffman - Morphick Inc"
    description = "Scanning for a filename within an ACE file by searching the offsets within the header"
 
  strings:
    $header = { 2a 2a 41 43 45 2a 2a }
    $filename = /malicious\.exe/ nocase

  condition:
    for all of ($header*) : ( $filename in (@+88-7..@+88-7+uint16(@+86-7)))
}
