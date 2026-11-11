/*
   Detects XMRig-family Monero miners (ELF binaries or their config/scripts).
   MITRE ATT&CK: T1496 Resource Hijacking
   Test: yara -s detections/yara/linux_cryptominer_xmrig.yar <file>
*/
rule Linux_CryptoMiner_XMRig
{
    meta:
        author      = "Madina Zhakina"
        description = "XMRig / Monero miner strings"
        date        = "2026-11-08"
        mitre       = "T1496"

    strings:
        $s1 = "xmrig" ascii nocase
        $s2 = "stratum+tcp://" ascii
        $s3 = "stratum+ssl://" ascii
        $s4 = "--donate-level" ascii
        $s5 = "randomx" ascii nocase
        $s6 = "cryptonight" ascii nocase
        $s7 = "\"pools\"" ascii
        $s8 = "moneroocean" ascii nocase
        $s9 = "c3pool" ascii nocase

    condition:
        filesize < 15MB and 2 of them
}
