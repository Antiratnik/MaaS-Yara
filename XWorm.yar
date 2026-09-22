/*
    YARA Rule Set: XWorm RAT / Banker / Worm (Client & C2 Server)
    Author: Antirat | Cybersec Lab
    Reference: https://github.com/Antiratnik
    Date: 2026-09-22
    License: BSD 3-Clause

    Note:
    Rules are designed to be campaign-agnostic and configuration-independent.
    They do not rely on dynamic C2 hosts, ports, campaign groups, mutexes,
    or pre-shared AES communication keys, ensuring reliable detection of
    both custom-configured and obfuscated builds.
*/

import "pe"

rule MALW_XWorm_Generic_Client {
    meta:
        description = "Detects XWorm RAT client stubs across campaigns, versions and configurations"
        author = "Antirat | Cybersec Lab"
        reference = "https://github.com/Antiratnik"
        date = "2026-09-22"
        malware_family = "XWorm"
        threat_type = "Remote Access Trojan / Spyware / Worm"
        confidence = "High"

    strings:
        // 1. Structural persistence & evasion commands (stored as UTF-16LE in .NET #US stream)
        $cmd_task_admin = "/create /f /RL HIGHEST /sc minute /mo 1 /tn" wide
        $cmd_task_user  = "/create /f /sc minute /mo 1 /tn" wide
        $cmd_def_path   = "Add-MpPreference -ExclusionPath" wide
        $cmd_def_proc   = "Add-MpPreference -ExclusionProcess" wide
        $cmd_run_reg    = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $cmd_wscript    = "WScript.Shell" wide

        // 2. USB Worm LNK infection mechanics (invariant across builds)
        $usb_icon_reg   = "HKEY_LOCAL_MACHINE\\software\\classes\\folder\\defaulticon\\" wide
        $usb_cmd_expl   = "&start explorer " wide
        $usb_cmd_start  = "/c start " wide

        // 3. XWorm proprietary C2 protocol commands (invariant across builds)
        $p_ddos_start   = "StartDDos" wide ascii
        $p_ddos_stop    = "StopDDos" wide ascii
        $p_url_hide     = "Urlhide" wide ascii
        $p_url_open     = "Urlopen" wide ascii
        $p_rem_plugins  = "RemovePlugins" wide ascii
        $p_save_plugin  = "savePlugin" wide ascii
        $p_send_plugin  = "sendPlugin" wide ascii
        $p_pc_logoff    = "PCLogoff" wide ascii
        $p_pc_restart   = "PCRestart" wide ascii
        $p_pc_shutdown  = "PCShutdown" wide ascii
        $p_hosts_msg    = "HostsMSG" wide ascii
        $p_hosts_err    = "HostsErr" wide ascii

        // 4. Native API / Hooking / Obfuscation indicators
        $api_hook_kbd   = "WHKEYBOARDLL" ascii
        $api_dpi_aware  = "SetProcessDpiAwareness" ascii
        $api_clp_listen = "AddClipboardFormatListener" ascii
        $api_cam_driver = "capGetDriverDescriptionA" ascii
        $api_cam_window = "capCreateCaptureWindowA" ascii

        // 5. Code-level .NET type and method names (for unobfuscated / lightly obfuscated stubs)
        $net_stub_main  = "Stub.Main" ascii
        $net_stub_aes   = "Stub.AlgorithmAES" ascii
        $net_stub_log   = "Stub.XLogger" ascii
        $net_stub_clip  = "Stub.Clipper" ascii
        $net_stub_usb   = "Stub.USB" ascii
        $net_enc_method = "AES_Encryptor" ascii
        $net_dec_method = "AES_Decryptor" ascii

    condition:
        // Validate PE format & size bounds (< 5MB for client payloads)
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
        filesize < 5MB and
        (
            // Scenario A: Unobfuscated/lightly packed build (matches class names + protocol/cmd strings)
            ((2 of ($net_stub_*) or all of ($net_enc_method, $net_dec_method)) and (2 of ($p_*) or 2 of ($cmd_*))) or

            // Scenario B: Obfuscated build (renamed classes, but internal commands and protocol tokens intact)
            (2 of ($cmd_task_admin, $cmd_task_user, $cmd_def_path, $cmd_def_proc, $cmd_run_reg) and 2 of ($usb_*) and 2 of ($p_*)) or

            // Scenario C: Behavioral match on persistence + evasion + protocol + APIs
            (2 of ($cmd_*) and 2 of ($p_*) and 1 of ($api_*)) or

            // Scenario D: High-confidence protocol command cluster
            (5 of ($p_*))
        )
}

rule MALW_XWorm_C2_Server {
    meta:
        description = "Detects XWorm C2 Controller / Builder Panel software"
        author = "Antirat | Cybersec Lab"
        reference = "https://github.com/Antiratnik"
        date = "2026-09-22"
        malware_family = "XWorm"
        threat_type = "Command and Control / Builder Panel"
        confidence = "High"

    strings:
        // Internal form types
        $f_main        = "Xworm.Main" ascii wide
        $f_builder     = "Xworm.Builder" ascii wide
        $f_hvnc        = "Xworm.HVNC" ascii wide
        $f_fm          = "Xworm.FM" ascii wide
        $f_clipper     = "Xworm.Clipper" ascii wide
        $f_keylogger   = "Xworm.Keylogger" ascii wide
        $f_ransomware  = "Xworm.Ransomware" ascii wide
        $f_tbot        = "Xworm.TBotNotify" ascii wide
        $f_tcpconn     = "Xworm.TcpConnectionForm" ascii wide

        // Server-specific UI and protocol artifacts
        $s_botkiller   = "BotkillerToolStripMenuItem" ascii wide
        $s_discord     = "DiscordTokenToolStripMenuItem" ascii wide
        $s_telegram    = "TelegramSessionToolStripMenuItem" ascii wide
        $s_perf        = "Xworm.Performance" ascii wide
        $s_happs       = "Xworm.HApps" ascii wide

    condition:
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
        (
            4 of ($f_*) or
            (2 of ($f_*) and 2 of ($s_*))
        )
}
