/*
   Generic detection for Mirai-style IoT bots (statically linked ELF, busybox
   tricks, hard-coded default credentials, flood attack names).
   MITRE ATT&CK: T1498 Network DoS (payload), T1110 Brute Force (spreading)
*/
rule Linux_Mirai_Like_Bot
{
    meta:
        author      = "Madina Zhakina"
        description = "Mirai-family / IoT botnet ELF"
        date        = "2026-11-08"

    strings:
        $busybox  = "/bin/busybox" ascii
        $ecchi    = "ECCHI" ascii
        $mirai    = "MIRAI" ascii
        $watchdog = "/dev/watchdog" ascii
        $selfrep  = "/proc/self/exe" ascii
        $cred1    = "xc3511" ascii
        $cred2    = "vizxv" ascii
        $cred3    = "7ujMko0admin" ascii
        $flood1   = "udpplain" ascii nocase
        $flood2   = "greeth" ascii nocase
        $flood3   = "tcpraw" ascii nocase
        $http     = "POST /cdn-cgi/" ascii

    condition:
        uint32(0) == 0x464c457f and filesize < 2MB and
        ( 1 of ($ecchi, $mirai) or
          ($busybox and $watchdog) or
          2 of ($cred*) or
          2 of ($flood*, $http) or
          ($selfrep and $busybox and 1 of ($cred*)) )
}
