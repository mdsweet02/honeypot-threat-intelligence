/*
   Shell-script droppers ("bins.sh", "x.sh") that download one binary per CPU
   architecture, chmod it and run it - the most common file seen on SSH honeypots.
   MITRE ATT&CK: T1105 Ingress Tool Transfer, T1059.004 Unix Shell
*/
rule Linux_Shell_Multiarch_Dropper
{
    meta:
        author      = "Madina Zhakina"
        description = "Multi-architecture botnet dropper script"
        date        = "2026-11-08"

    strings:
        $dl1   = "wget " ascii
        $dl2   = "curl " ascii
        $dl3   = "tftp " ascii
        $dl4   = "ftpget " ascii
        $chmod = /chmod (\+x|7[0-7][0-7])/ ascii
        $tmp   = /cd \/(tmp|var\/run|mnt|root)/ ascii
        $a1    = "mips" ascii
        $a2    = "mpsl" ascii
        $a3    = "arm7" ascii
        $a4    = "x86" ascii
        $a5    = "ppc" ascii
        $a6    = "m68k" ascii
        $a7    = "sh4" ascii

    condition:
        filesize < 100KB and
        1 of ($dl*) and $chmod and
        ($tmp or 3 of ($a*))
}
