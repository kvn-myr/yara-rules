rule Ransomware_ZZ_TA2101_Maze : tag1
{
    meta:
        author = "Kevin Gomez Buquerin @kgbuquerin"
        description = "Detects Maze ransomware"
        date = "2020-04-30"
        last_modified = "2020-05-02"
        tlp = "WHITE"
        hash0 = "c11b964916457579a268a36e825857866680baf1830cd6e2d26d4e1e24dec91b"
        hash1 = "4218214f32f946a02b7a7bebe3059af3dd87bcd130c0469aeb21b58299e2ef9a"
        hash2 = "4e1f7d397a07477bc3da1e1185a5960475817e9d04529b5bcc2068830262fa1b"
        hash3 = "67f338c9f15b000aedac1d736fbce1ab27fd72a10d397315ba724b1dccf4e834"
        hash4 = "aad2869ebbd92c22c3366bccf857522686e70c8f541d9164bc483dc44244dbcc"
        hash5 = "04e22ab46a8d5dc5fea6c41ea6fdc913b793a4e33df8f0bc1868b72b180c0e6e"
        hash6 = "1161b030293e58d15b6a6a814a61a6432cf2c98ce9d156986157b432f3ebcf78"
        hash7 = "58fe9776f33628fd965d1bcc442ec8dc5bfae0c648dcaec400f6090633484806"
        hash8 = "5c9b7224ffd2029b6ce7b82ea40d63b9d4e4f502169bc91de88b4ea577f52353"
        hash9 = "65f2bf2bf25524b4b9c41e4ff55ede002cc527aab0840c5bcbeb06f7c245227f"
        hash10 = "83f8ce81f71d6f0b1ddc6b4f3add7a5deef8367a29f59b564c9539d6653d1279"
        hash11 = "91514e6be3f581a77daa79e2a4905dcbdf6bdcc32ee0f713599a94d453a26fc1"
        hash12 = "b30bb0f35a904f67d3ac0082c59770836cc415dc5b7225be04e8d7c79bde73be"
        hash13 = "c040defb9c90074b489857f328d3e0040ac0ddab26cde132f17cccae7f1309cc"

    strings:
        $s0 = "LJUBLJANA-POLJE1" fullword ascii
        $s1 = "GO ONLINE d.o.o.1" fullword ascii
        $s2 = "GO ONLINE d.o.o.0" fullword ascii
        $s3 = "ka cesta 1881" fullword ascii
        $s4 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXX" ascii
        $s5 = "youaremyshame!!" fullword ascii
        $s6 = "you are nothing" fullword ascii
        $s7 = "youaremyshame!!" fullword ascii
        $s8 = "you are nothing" fullword ascii
        $s9 = "another random string blablabla" fullword ascii
        $s10 = "--demonslay335mode" fullword ascii
        $s11 = "Installed! (not a malware trust me)" fullword ascii
        $s12 = "--killthetrump" fullword ascii
        $s13 = "japanese shiteater" fullword ascii
        $s14 = "Gruja is a fucking noob, what next shit name will you invent? idiot // (c) malwarehunterteam" fullword ascii
        $s15 = "--malwarehunterteam=superjokesilikeit" fullword ascii
        $s16 = "C:\\fakepath\\fakepdb.pdb" fullword ascii
        
        $a0 = "C:\\Wuhan\\Lab\\coronashit.pdb" fullword ascii
        $a2 = "C:\\Users\\Club\\Desktop\\ProxyDll-master\\distrib\\01_tryhard\\x64_release\\version.pdb" fullword ascii
        $a3 = "{00ab6-66ab84-77413}" fullword ascii
        $a4 = "C:\\xagehusujoz kucosisukakovuvuluh xukido-nub.pdb" fullword ascii
        $a5 = "75\\bin\\yalos.pdb" fullword ascii
        $a6 = "c:\\near\\very\\grew\\PeopleBelieve.pdb" fullword ascii
        $a7 = "C:\\random\\fucking\\path\\to\\fucking\\idiotic\\nonexisting\\file\\with\\pdb\\extension.pdb" fullword ascii
        $a8 = "C:\\shit\\gavno.pdb" fullword ascii
        $a9 = " Go build ID: \"MaXny4z1sHP8RbJDzuSf/0D6ZmoHBUrwEOqoXo1lb/m4beCQvGlP7G0mmaWD8F/tur-DqePMQ959WsDZc_4\"" fullword ascii
        $a10 = "C:\\magabaxasoti_jig\\batupo100\\tizizuhicezixa-tiyo vuyivowuxelu.pdb" fullword ascii
        $a11 = "C:\\zelo35_fixomekafeyu\\bimudupalij_sisedizesolovi.pdb" fullword ascii
        $a12 = "bin\\cacofev.pdb" fullword ascii

    condition:
        uint16(0) == 0x5A4D and 
        filesize < 800KB and
        (9 of ($s*) or 1 of ($a*) or 18 of them)
}
