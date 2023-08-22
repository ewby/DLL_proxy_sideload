**Just a simple DLL Proxy Sideload template.**

This will allow you to sideload into a "vulnerable" process without calling DllMain which, more likely than not, will cause loader lock for the C2 of your choosing. At runtime your shellcode is prepped to be loaded when the process calls your proxy function, other functions you're mimicing from the original DLL are forwarded to the original DLL, and the original function you're targeting gets called. All intended for functionality and stability of the process you're injected into, as well as your malware.

DLL used in this example is FxsCompose.dll which will be injected into WFS.exe, others can be found with Frida or WFH (Windows Feature Hunter).