import "pe"

rule Entrypoint_Outside_Of_EXE_Sections
{
  meta:
    author = "@infoseckitten"
    description = "Executables where EP sits outside of executable section ranges"

  condition:
    //DLL check
    pe.entry_point != 0 and
    not pe.is_dll() and

    //Does EP sit in an executable section?
    not for any i in (0..pe.number_of_sections) :
        (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE and
         pe.entry_point >= pe.sections[i].raw_data_offset and
         pe.entry_point <= pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size)

    //Check for EXECUTABLE IMAGE
    and pe.characteristics & pe.EXECUTABLE_IMAGE
}
