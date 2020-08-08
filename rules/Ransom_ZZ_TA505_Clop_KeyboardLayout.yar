rule Ransom_ZZ_TA505_Clop_KeyboardLayout
{
    meta:
        author = "Kevin Gomez Buquerin @kgbuquerin"
        description = "Detect cl0p ransomware keyboard layout check"
        reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/clop-ransomware/"
        date = "2020-05-04"
        last_modified = "2020-05-04"
        tlp = "WHITE"
    
    strings:
        $h0 = {3d 37 04 00 00 [4] 05 e7 fb ff ff 83 f8 12 [0-20] 3d 2c 08 00 00}
    
    condition:
        uint16(0) == 0x5a4d and 
        filesize < 800KB and
        ($h0)
}

