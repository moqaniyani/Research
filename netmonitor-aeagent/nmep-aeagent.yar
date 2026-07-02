rule Unauthorized_NetMonitor_Agent_InMemory {
    meta:
        author = "Milad Moghniyani"
        description = "Detects unauthorized NetMonitor agent artifacts, C2 domains, and control sequences in memory dumps"
        threat_level = "Critical"
        mitre_technique = "T1036.005 / T1071.001"
        date = "2026-07-02"

    strings:
        // ۱. رشته‌های مربوط به نام‌های پردازه‌های غیراستاندارد و نام اصلی ابزار
        $proc_1 = "aeagent.exe" ascii wide nocase
        $proc_2 = "nmep_ctrlagent.exe" ascii wide nocase
        $proc_3 = "Net Monitor for Employees" ascii wide nocase

        // ۲. دامنه‌ و نشانگرهای سرور کنترل و فرمان (C2)
        $c2_domain = "networklookout.com" ascii wide nocase

        // ۳. آرگومنت‌ها، مسیرها یا دستورات داخلی بدافزار برای کنترل کلاینت
        $cmd_1 = "wspport" ascii wide nocase     // وب‌سوکت یا پورت‌های ارتباطی مانیتورینگ
        $cmd_2 = "screen_cap" ascii wide nocase  // قابلیت اسکرین‌شات
        $cmd_3 = "key_log" ascii wide nocase     // قابلیت کی‌لاگر

    condition:
        // منطق شکار در حافظه: حضور نام پردازه‌های مشکوک به همراه دامنه‌ی C2 یا ابزارهای مانیتورینگ غیرمجاز
        (any of ($proc_*)) and ($c2_domain or any of ($cmd_*))
}