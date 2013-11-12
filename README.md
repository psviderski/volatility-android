# Volatility-android

A plugin for [Volatility][1] that adds support for universal memory forensic analysis of Android systems. This solution doesn't depend on precreated Volatility profiles, but instead it automatically performs the calculation of offsets in kernel data structures at run time.

This is the repository for the coding part of the [graduate paper][2] of [Pavel Sviderski][3]. The paper topic is "General approach to recovery of process address space using Android OS memory image".

## Usage

    $ ./vol.py -f ram_image_file --profile=LinuxAutoARM command_name [command options]

## Commands

### linux_auto_ksymbol

    ./vol.py [...] linux_auto_ksymbol -K init_task

    Volatile Systems Volatility Framework 2.3_alpha
    Kernel symbol: init_task @ 0xc05d3678

### linux_auto_dtblist

    $ ./vol.py [...] linux_auto_dtblist

    Volatile Systems Volatility Framework 2.3_alpha
    DTB
    ----------
    0x12c04000
    0x12c28000
    0x13844000
    0x13898000
    0x138dc000
    0x1391c000
    0x13978000
    0x139d4000
    0x13a58000
    0x13a5c000
    [...]
    0x2bd54000
    0x2bdf4000
    0x2be00000
    0x2c1cc000
    0x2c1d8000
    0x2c248000
    0x2c28c000
    0x2c2bc000
    0x2c2c8000
    0x2caa4000

### linux_auto_pslist

    $ ./vol.py [...] linux_auto_pslist

    Volatile Systems Volatility Framework 2.3_alpha
    Offset     Name                 DTB
    ---------- -------------------- ----------
    0xd9c28c60 init                 0x2c2bc000
    0xd9c28040 kthreadd             ----------
    0xd9c2ec80 ksoftirqd/0          ----------
    0xd9c34080 khelper              ----------
    [...]
    0xd62e43e0 ndroid.systemui      0x28ee8000
    0xd62e5000 .android.htcime      0x28f64000
    0xd63b50e0 m.android.phone      0x28fb8000
    0xd0c22500 om.htc.launcher      0x2384c000
    0xd0e2e780 e.process.gapps      0x23a34000
    0xd0ea6080 com.htc.bgp          0x23aac000
    0xc0d0a740 loop0                ----------
    0xd914d1e0 kdmflush             ----------
    0xcc257080 kcryptd_io           ----------
    0xc34224e0 kcryptd              ----------
    0xc0c0e0a0 htcime:provider      0x1dc64000
    0xc0c882c0 LocationService      0x16174000
    0xd255a6c0 d.process.acore      0x138dc000
    0xc54023e0 tc.android.mail      0x1eca4000
    0xc12d53c0 oid.htccontacts      0x13ef8000
    0xc56405e0 com.android.mms      0x1ecfc000
    0xc37c02e0 htc.taskmanager      0x28c40000
    0xcb265380 Smack Packet Ha      0x23a34000
    ---------- -------------------- 0x12c04000
    ---------- -------------------- 0x12c28000
    ---------- -------------------- 0x13844000
    [...]
    ---------- -------------------- 0x2c1d8000
    ---------- -------------------- 0x2c248000
    ---------- -------------------- 0x2c28c000

### linux_auto_dump_map

    $ ./vol.py [...] linux_auto_dump_map -D ./dump_dir -e 0xc0000000
    [...]

    $ ls -1 ./dump_dir
    DTB_0x12c28000.bin
    DTB_0x12c28000.bin.index
    DTB_0x13844000.bin
    DTB_0x13844000.bin.index
    [...]
    m.android.phone_0x28fb8000.bin
    m.android.phone_0x28fb8000.bin.index
    mediaserver_0x2bc40000.bin
    mediaserver_0x2bc40000.bin.index
    ndroid.systemui_0x28ee8000.bin
    ndroid.systemui_0x28ee8000.bin.index
    netd_0x2bc34000.bin
    netd_0x2bc34000.bin.index
    [...]


[1]: https://code.google.com/p/volatility/ "The Volatility Framework home page @ Google Code"
[2]: http://se.math.spbu.ru/SE/diploma/2013/s/SviderskiPavel_thesis.pdf "Graduate paper (in Russian)"
[3]: mailto:pavel@psviderski.name
