# IDA cLEMENCy Tools

[cLEMENCy](https://blog.legitbs.net/2017/07/the-clemency-architecture.html) is an architecture developed by LegitBS for use during the Defcon 25 Capture the Flag event.
The architecure was unsupported by IDA at the outset of the competition. It seemd useful to have disassembler support outside the emulatr/disassembler published in conjunction
with the cLEMENCy specification 24 hours prior to commencement of the competition. These tools are the result of that development effort. This project contains:

* A scripted IDA loader module to create the basic memory layout and handle the loading of 9-bit, middle-endian, cLEMENCy executables.
* A scripted IDA processor module to handle disassembly and assembly tasks
* A scripted IDA plugin to allow for dumping modified database content back to a packed 9-bit, middle-endian file (scripted loaders do not support the save_file functionality).
* A scripted IDA plugin to assist with fixing up poorly disassembled functions that might branch/call into regions that continue to be marked as data blocks.

## Getting Started

Here <idadir> refers to the root directory of your IDA installation

* Copy clemency_proc.py to <idadir>/procs/clemency_proc.py
* Copy clemency_ldr.py to <idadir>/loaders/clemency_ldr.py
* Copy clemency_dump.py to <idadir>/plugins/clemency_dump.py
* Copy clemency_fix.py to <idadir>/plugins/clemency_fix.py

Note that clemency_ldr.py will show up as an available loader for all file formats because cLEMENCy binaries have no distinct file format. If you
elect to use the clemency_ldr, you should also select the corresponding clemency_proc from the Processors drop-down in the load file dialog.

### Prerequisites

A working copy of IDA Pro with compatible Python installation allowing for the use of Python plugins and scripts.

### Installing

See above

## Built With

* A sledghammer

## Contributing

Probably not worth your time

## Versioning

This is probably all there will ever be

## Authors

* **Chris Eagle** - *Initial work* - 
* **Shellphish** - *The cLEMENCy Assembler bits*

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* All the members of Shellphish for letting me join the fun, and who contributed much code and many ideas to these tools
