# ArgumentSpoofer
![C](https://img.shields.io/badge/Language-C-blue?style=for-the-badge&logo=C)

```
A code that allows you to spoofing arguments when starting a process; at the moment.
The substitution also worked on Process-Hacker - which displayed fake arguments.
```

# ✨ Code-Args:
```c
113    LPWSTR szStartupArgs = L"powershell.exe AAAAAAAAAAAAAAAAA"; // Your fake-argumnets
114    LPWSTR szRealArgs = L"powershell.exe -NoExit calc.exe"; // Your real-arguments
```

# 📒 Proof:
<img alt="screen" width="750" src="proof.png">
