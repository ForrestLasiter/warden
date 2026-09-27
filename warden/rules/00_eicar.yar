/*
   EICAR test file detection.

   The EICAR string is the industry-standard *harmless* test pattern that every
   antivirus is expected to flag. It is not malware - it lets you prove the
   scanner works without touching a real sample.

   Create a test file:
     printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file (harmless)"
        severity    = "critical"
        author      = "Warden"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
