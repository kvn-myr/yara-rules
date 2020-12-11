# Yara rules

This repository contains different yara rules I wrote.

Here is the Yara rule structure I use. You can find the Visual Studio Code snipped in the file yara-snipped.txt
```
// ThreatTypes: Ransom, APT, ...
// ZZ: (location) DE, EN, ZZ for unkown, ...
// GroupName: APT41, FIN11, ...
// MalwareName: Ekans, SDBBot, ...
rule ThreatType_ZZ_GroupName_MalwareName
{
  meta:
    description = "description"
    author = "author"
    date = "YYYY-MM-DD"
    last_modified =  "YYYY-MM-DD"
    reference = "reference"
    tlp = "TLP:X"
    hash = "hash"

  strings:
    $s0 = "string"
    
    $a0 = "artifact"

    $b0 = {FF}

  condition:
    condition
}
```
