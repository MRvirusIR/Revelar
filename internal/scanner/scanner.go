package scanner

import (
    "fmt"
)

func ProcessDomain(domain string, active bool) {
    fmt.Printf("[*] Scanning domain: %s (active=%v)\n", domain, active)
    // TODO: اضافه کردن لاجیک اصلی اسکن (DNS, subfinder, httpx, ...)
}

func ProcessFile(file string, active bool) {
    fmt.Printf("[*] Scanning domains from file: %s (active=%v)\n", file, active)
    // TODO: باز کردن فایل و اسکن هر دامنه
}
