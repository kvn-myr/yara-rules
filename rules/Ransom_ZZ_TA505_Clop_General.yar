rule Ransom_ZZ_TA505_Clop_General
{
    meta:
        author = "Kevin Gomez Buquerin @kgbuquerin"
        description = "Detect cl0p ransomware"
        reference = "https://www.bleepingcomputer.com/news/security/cryptomix-clop-ransomware-says-its-targeting-networks-not-computers/"
        date = "2020-05-04"
        last_modified = "2020-05-04"
        tlp = "WHITE"
        hash0 = "2ceeedd2f389c6118b4e0a02a535ebb142d81d35f38cab9a3099b915b5c274cb"
        hash1 = "a867deb1578088d066941c40e598e4523ab5fd6c3327d3afb951073bee59fb02"
    
    strings:
        $s0 = "Caso_M41nt_Clop.bin" fullword ascii
        $s1 = "clop.bin" fullword ascii

        $h0 = {3d 37 04 00 00 ?? ?? ?? ?? 05 e7 fb ff ff 83 f8 12 [0-20] 3d 2c 08 00 00} // keyboard layout
    
    condition:
        uint16(0) == 0x5a4d and 
        filesize < 800KB and
        (1 of ($s*) or $h0)
}