import "pe"

rule WebRat_Salat_ConfigVault
{
    meta:
        description   = "WebRat/Salat Stealer - encrypted config vault (stride-checked)"
        author        = "Antirat-team"
        date          = "2026-09-15"
        reference     = "WebRat-Salat-Stealer-Analysis.md"
        tlp           = "CLEAR"
        family        = "Salat / WebRat"
        scope         = "unpacked"
        sample_sha256 = "AEBB8883342BF67E60F731954A7508544E9D4DCF11699B65C37270AA77BDE030"

    strings:
        $magic = { A5 A7 A5 A5 }

    condition:
        uint16(0) == 0x5A4D and
        filesize > 4MB and filesize < 32MB and
        #magic >= 5 and
        for any i in (1..#magic - 1) : (
            @magic[i+1] - @magic[i] == 0x204
        )
}

rule WebRat_Salat_Family
{
    meta:
        description   = "WebRat/Salat Stealer - family-level detection (variant-agnostic)"
        author        = "Antirat-team"
        date          = "2026-09-15"
        reference     = "WebRat-Salat-Stealer-Analysis.md"
        tlp           = "CLEAR"
        family        = "Salat / WebRat"
        scope         = "unpacked"
        severity      = "high"

    strings:
        $pkg_main    = "salat/main.go"
        $pkg_init    = "salat/init.go"
        $pkg_task    = "salat/task.go"
        $pkg_funcs   = "salat/funcs.go"
        $pkg_sets    = "salat/sets.go"
        $pkg_tsc     = "salat/tsc.go"
        $pkg_shot    = "salat/screenshot/screenshot.go"

        $sym_getbc   = "main.getBC"
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

        $tonlib      = "github.com/xssnick/tonutils-go"

    condition:
        uint16(0) == 0x5A4D and
        filesize > 1MB and
        pe.is_pe and
        pe.sections[pe.number_of_sections - 1].name == ".gopclntab" and
        (
            (3 of ($pkg_*) and $tonlib) or
            (2 of ($pkg_*) and 2 of ($sym_*)) or
            ($tonlib and $sym_tonaddr and 1 of ($pkg_*)) or
            (4 of ($sym_*) and 1 of ($pkg_*))
        )
}

rule WebRat_Salat_Variant_0_28_1
{
    meta:
        description   = "WebRat/Salat Stealer - variant 0.28.1 (victim-ID salt)"
        author        = "Antirat-team"
        date          = "2026-09-15"
        reference     = "WebRat-Salat-Stealer-Analysis.md"
        tlp           = "CLEAR"
        family        = "Salat / WebRat"
        variant       = "0.28.1"
        scope         = "unpacked"
        sample_md5    = "3FEFA038111DA3D1AA25C9EA14CC9A5C"
        sample_sha256 = "AEBB8883342BF67E60F731954A7508544E9D4DCF11699B65C37270AA77BDE030"

    strings:
        $salt   = "XG5zvsPtiPVBjRcOivTJ"
        $tonlib = "github.com/xssnick/tonutils-go"

    condition:
        uint16(0) == 0x5A4D and
        filesize > 1MB and
        $salt and
        $tonlib
}

rule WebRat_Salat_HighConfidence
{
    meta:
        description   = "WebRat/Salat Stealer - high-confidence combined detection"
        author        = "Antirat-team"
        date          = "2026-09-15"
        reference     = "WebRat-Salat-Stealer-Analysis.md"
        tlp           = "CLEAR"
        family        = "Salat / WebRat"
        scope         = "unpacked"
        severity      = "high"
        sample_md5    = "3FEFA038111DA3D1AA25C9EA14CC9A5C"
        sample_sha256 = "AEBB8883342BF67E60F731954A7508544E9D4DCF11699B65C37270AA77BDE030"

    strings:
        $magic       = { A5 A7 A5 A5 }
        $pkg_main    = "salat/main.go"
        $pkg_init    = "salat/init.go"
        $pkg_task    = "salat/task.go"
        $pkg_tsc     = "salat/tsc.go"
        $tonlib      = "github.com/xssnick/tonutils-go"
        $sym_getbc   = "main.getBC"
        $sym_tonaddr = "decodeFromTonAddress"
        $sym_hvnc    = "sepDesktop"
        $sym_abk     = "GetAppBoundKey"
        $salt        = "XG5zvsPtiPVBjRcOivTJ"

    condition:
        uint16(0) == 0x5A4D and
        filesize > 4MB and
        pe.is_pe and
        pe.sections[pe.number_of_sections - 1].name == ".gopclntab" and
        #magic >= 5 and
        for any i in (1..#magic - 1) : (
            @magic[i+1] - @magic[i] == 0x204
        ) and
        (
            $salt or
            ($tonlib and $sym_tonaddr) or
            ($sym_getbc and $tonlib)
        ) and
        (
            2 of ($pkg_*) or
            $sym_hvnc or
            $sym_abk
        )
}