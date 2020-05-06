rule Ransomware_ZZ_TA505_Clop_General
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

rule Ransomware_ZZ_TA505_Clop_Encryption
{
    meta:
        author = "Kevin Gomez Buquerin @kgbuquerin"
        description = "Detects Maze ransomware encryption routine"
        date = "2020-05-05"
        last_modified = "2020-05-05"
        tlp = "WHITE"
        hash0 = "6d8d5aac7ffda33caa1addcdc0d4e801de40cb437cf45cface5350710cde2a74"
    
    strings:
        $b = {8b 4? ?? 83 c1 01 89 4? ?? 81 7? ?? 84 03 00 00 73 ?? 8b 5? ?? 8b 4? ?? 8b 0c ?? 89 8? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 9? ?? ?? ?? ?? 8b 8? ?? ?? ?? ?? 2b 4? ?? 89 8? ?? ?? ?? ?? 8b 4? ?? 83 e9 50 89 4? ?? 8b 9? ?? ?? ?? ?? 33 9? ?? ?? ?? ?? 89 9? ?? ?? ?? ?? 8b 4? ?? 2d e8 03 00 00 89 4? ?? c1 8? ?? ?? ?? ?? 07 8b 8? ?? ?? ?? ?? 33 8? ?? ?? ?? ?? 89 8? ?? ?? ?? ?? 8b 5? ?? 8b 4? ?? 8b 8? ?? ?? ?? ?? 89 0c 90 e9 ?? ?? ?? ??}
    
    condition:
        uint16(0) == 0x5a4d and
        filesize < 1800KB and
        all of them
}