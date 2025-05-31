rule Detect_SetWindowsHookEx
{
    meta:
        description= "Rule for detecting use of SetWindowsHookEx Api by any DLL."
    strings:
        $api1 = "SetWindowsHookEx" ascii
        $api2 = "GetAsyncKeyState" ascii
        $signature = "keylogger_signature_test" ascii
    condition:
        any of them
}

