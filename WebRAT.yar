rule WebRat_Salat_ConfigVault
{
    meta:
        description   = "WebRat/Salat Stealer"
        author        = "Antirat-team"
        date          = "2026-09-15"
        reference     = "WebRat-Salat-Stealer-Analysis.md"
        tlp           = "CLEAR"
        family        = "Salat / WebRat"
        sample_sha256 = "AEBB8883342BF67E60F731954A7508544E9D4DCF11699B65C37270AA77BDE030"

    strings:
        $magic = { A5 A7 A5 A5 }

    condition:
        uint16(0) == 0x5A4D and
        filesize > 4MB and filesize < 32MB and
        #magic >= 5
}

rule WebRat_Salat_Strings
{
    meta:
        description   = "WebRat/Salat Stealer - plaintext Go package paths, symbol names and literals"
        author        = "threat-intel"
        date          = "2026-06-12"
        reference     = "WebRat-Salat-Stealer-Analysis.md"
        tlp           = "CLEAR"
        family        = "Salat / WebRat"

    strings:
        $pkg_main    = "salat/main.go"
        $pkg_init    = "salat/init.go"
        $pkg_task    = "salat/task.go"
        $pkg_funcs   = "salat/funcs.go"
        $pkg_sets    = "salat/sets.go"
        $pkg_tsc     = "salat/tsc.go"
        $pkg_shot    = "salat/screenshot/screenshot.go"

        $sym_getbc   = "main.getBC"
        $sym_bestm   = "main.getBestMethod"
        $sym_tonaddr = "decodeFromTonAddress"
        $sym_tonres  = "tryTonResolve"
        $sym_wsrecv  = "recvWss"
        $sym_hvnc1   = "sepDesktop"
        $sym_hvnc2   = "ffdesktop"
        $sym_cam     = "ffwcam"
        $sym_mic     = "ffwmic"
        $sym_abk     = "GetAppBoundKey"
        $sym_abp     = "StartAPPB"
        $sym_abpd    = "decryptAPPB"
        $sym_lsass   = "findLsassProcess"
        $sym_steam   = "decodeSteam"
        $sym_vdf     = "parseVdf"

        $salt        = "XG5zvsPtiPVBjRcOivTJ"
        $tonlib      = "github.com/xssnick/tonutils-go"
        $biba        = "biba"
        $masq        = "svchost.exe"
        $dpi         = "SetProcessDPIAware"

    condition:
        (
            uint16(0) == 0x5A4D and
            filesize > 1MB
        ) and
        (
            2 of ($pkg_*) or
            $salt or
            ($tonlib and 1 of ($sym_*)) or
            3 of ($sym_*) or
            ($biba and ($masq or 1 of ($pkg_*)))
        )
}

rule WebRat_Salat_HighConfidence
{
    meta:
        description   = "WebRat/Salat Stealer - high-confidence combined detection"
        author        = "threat-intel"
        date          = "2026-06-12"
        reference     = "WebRat-Salat-Stealer-Analysis.md"
        tlp           = "CLEAR"
        family        = "Salat / WebRat"
        severity      = "high"
        sample_md5    = "3FEFA038111DA3D1AA25C9EA14CC9A5C"
        sample_sha256 = "AEBB8883342BF67E60F731954A7508544E9D4DCF11699B65C37270AA77BDE030"

    strings:
        $magic       = { A5 A7 A5 A5 }

        $pkg_main    = "salat/main.go"
        $pkg_init    = "salat/init.go"
        $pkg_task    = "salat/task.go"
        $pkg_tsc     = "salat/tsc.go"

        $salt        = "XG5zvsPtiPVBjRcOivTJ"
        $tonlib      = "github.com/xssnick/tonutils-go"
        $sym_getbc   = "main.getBC"
        $sym_tonaddr = "decodeFromTonAddress"
        $sym_hvnc    = "sepDesktop"
        $sym_abk     = "GetAppBoundKey"

    condition:
        uint16(0) == 0x5A4D and
        filesize > 4MB and
        #magic >= 5 and
        (
            $salt or
            $tonlib or
            $sym_getbc or
            $sym_tonaddr
        ) and
        (
            1 of ($pkg_*) or
            $sym_hvnc or
            $sym_abk
        )
}