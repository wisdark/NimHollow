rule HKTL_Nim_NimHollow : EXE FILE HKTL
{
    meta:
        description = "Detects binaries generated with NimHollow"
        author = "snovvcrash"
        reference = "https://github.com/snovvcrash/NimHollow"
        
    strings:
        $mz = "MZ"
        $upx1 = {55505830000000}
        $upx2 = {55505831000000}
        $upx_sig = "UPX!"
        $nim1 = "fatal.nim" ascii fullword
        $nim2 = "winim" ascii
        $msg1 = { 5B 2D 5D 20 56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 4E 75 6D 61 }
        $func1 = { 68 6F 6C 6C 6F 77 53 68 65 6C 6C 63 6F 64 65 }
        $func2 = { 73 6C 65 65 70 41 6E 64 43 68 65 63 6B }

    condition:
        $mz at 0 or
        $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024) and
        filesize < 750KB and
        1 of ($nim*) and ($msg1 or 1 of ($func*))
}
