# device-discovery

C++17 command line utility for **Windows** that discovers the Linux device
connected directly to this PC, verifies its SSH endpoint, authenticates over SSH
and reports the IPv4 addresses of the device's two network interfaces.

The tool runs on the Windows PC; the Linux box is the device being discovered.

The user never supplies a subnet, an adapter or a target IP:

```bat
set DEVICE_SSH_PASSWORD=root
device-discovery.exe
```

---

## Physical setup

```text
Windows PC, Ethernet adapter (DHCP)  <- device-discovery.exe runs here
        |
        | direct Ethernet cable, no other stations on the link
        |
Target Linux device (static IP, sshd on TCP/22, two interfaces)
```

---

## Build

Requirements:

| Component | Notes                                                                |
| --------- | -------------------------------------------------------------------- |
| Windows   | Windows 8.1 / Server 2012 R2 or later (`GetIpNetTable2`)              |
| Compiler  | MSVC (Visual Studio 2019+ Build Tools) or MinGW-w64, C++17            |
| CMake     | 3.16 or later                                                         |
| libssh2   | `vcpkg install libssh2:x64-windows`                                   |

```bat
vcpkg install libssh2:x64-windows
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Artefacts: `build\Release\device-discovery.exe` plus the unit test binaries.
The build links against `ws2_32` and `iphlpapi`; no Npcap/WinPcap driver is
required.

Linux is intentionally **not** supported: the Linux machine is the device that
gets discovered, not the host running this tool.

---

## How discovery works

### 1. Local adapter selection (`src/network/interface_discovery.cpp`)

Adapters are enumerated with `GetAdaptersAddresses()` from `iphlpapi` (no
shelling out to `ipconfig` or `netsh`). An adapter becomes a *candidate* only
when all of the following hold:

* it is **not** a software loopback (`IF_TYPE_SOFTWARE_LOOPBACK`),
* its operational status is `IfOperStatusUp` (enabled **and** media connected,
  the Windows equivalent of `IFF_UP` + `IFF_RUNNING`),
* it has an IPv4 unicast address, from whose `OnLinkPrefixLength` the netmask is
  derived,
* neither its friendly name nor its description looks virtual
  (Hyper-V `vEthernet`, VMware/`VMnet`, VirtualBox, loopback pseudo-interfaces,
  TAP/OpenVPN/WireGuard/ZeroTier/Tailscale, Bluetooth, WAN miniports, …).

If **no** candidate remains the tool exits with `No suitable network interface
found.` If **several** candidates remain it lists them and exits rather than
silently guessing; `--interface "Ethernet 2"` can be used to disambiguate
(Windows adapter names contain spaces, so quote them).

### 2. Stage A — directly connected IPv4 subnet (`src/scanner/`)

From the selected interface the tool computes the network address, the broadcast
address and every host address of the directly connected subnet, excluding the
network address, the broadcast address and the PC's own address. Subnets larger
than `/22` (more than 1022 hosts) are refused so the tool never sweeps an
unbounded range; discovery then falls straight through to stage B.

Every address is probed through the fixed-size thread pool:

1. non-blocking `connect()` to TCP/22 with `WSAPoll()` and a 750 ms timeout,
2. read of the peer's identification string with a 1000 ms timeout,
3. the address only counts as a target when the identification **starts with
   `SSH-`** — an open port alone is never sufficient.

### 3. Stage B — static IP outside the DHCP subnet (`src/network/arp_discovery.cpp`)

Because the PC uses DHCP while the target uses a static address, the target may
live outside the PC's subnet. If stage A finds nothing, layer-2 discovery is
performed and is strictly limited to the directly connected link:

1. the Windows neighbour cache is read for that adapter with `GetIpNetTable2()`,
   keeping only resolved, reachable, non-multicast entries,
2. a `SOCK_RAW` socket is bound to the adapter's own IPv4 address and switched to
   promiscuous mode with `WSAIoctl(SIO_RCVALL)`, so it observes the whole link,
3. for the duration of the listening window (default 4000 ms) the source address
   of every captured IPv4 packet is recorded — including addresses outside the
   PC's own subnet, which is exactly the case this stage exists for,
4. the neighbour cache is read once more so hardware addresses learned during the
   window are attached to the observations.

No address outside the observed link is ever probed, and no arbitrary
private/Internet range is scanned. Layer-2 observation and TCP/SSH verification
are separate steps: each observed address is afterwards verified with the same
`SSH-` banner check as stage A.

`SIO_RCVALL` requires an **elevated** process. Without it the tool reports the
reason explicitly instead of claiming that no device exists:

```text
Error: No device discovered on Ethernet 2.
       cannot open a promiscuous capture socket on Ethernet 2: An attempt was made to
       access a socket in a way forbidden by its access permissions (error 10013)
       (layer-2 discovery needs an elevated process: re-run device-discovery from an
       Administrator command prompt)
```

Note that a raw socket capture sees IPv4 packets, not ARP frames, so a device
that is completely silent at the IP layer is only found through the neighbour
cache.

If a station is seen on the link but its address is not routable from the PC
(static IP in a foreign subnet), the diagnostic names the observed address, MAC
and the remedy (temporarily adding an address on that subnet) instead of
claiming that no device exists.

### 4. SSH authentication and remote command (`src/ssh/ssh_client.cpp`)

libssh2 is used — the SSH protocol is never re-implemented. The client
authenticates with username (default `root`) and the password supplied either on
the command line (`--ssh-password`) or taken from an environment variable, runs
`ifconfig` first (part of the device contract) and
falls back to `ip -4 addr` only if `ifconfig` is missing or fails. The session is
always disconnected and freed, and every phase has a timeout.

### 5. Interface parsing (`src/parser/ifconfig_parser.cpp`)

Both the net-tools format (`inet 192.168.10.50 netmask …`) and the
legacy/BusyBox format (`inet addr:192.168.10.50 Bcast:…`) are supported, as is
`ip -4 addr` output. Loopback, IPv6 addresses and entries without an IPv4
address are ignored; interface names are never assumed to be `eth0`/`eth1`
(`ens33`, `enp1s0`, `enp2s0`, … all work). If the number of non-loopback IPv4
interfaces is not two, the actual result is printed together with a warning —
nothing is discarded.

---

## SSH credentials

The password is **never** compiled into the binary and never printed.

```bat
set DEVICE_SSH_PASSWORD=root
device-discovery.exe

rem or with a different variable
set MY_SECRET=...
device-discovery.exe --ssh-password-env MY_SECRET

rem or directly on the command line
device-discovery.exe --ssh-user root --ssh-password root
```

`--ssh-password` takes precedence over the environment variable. Reading the
password from the environment remains the preferred option because command line
arguments of a process are readable by other processes on the machine.

### Host-key verification

Host-key verification is **configurable and, by default, non-fatal**:

* default (`Warn`): the key is compared against `%USERPROFILE%\.ssh\known_hosts`; an unknown
  or mismatching key is reported on stderr and in `host_key_status`, and the
  connection continues. This is the pragmatic default for a freshly connected
  device on an isolated cable, but it is **not** an authenticated key — the
  warning states so explicitly.
* `--strict-host-key`: an unknown or mismatching key aborts before any credential
  is sent.

Credentials are only transmitted after the peer has positively identified itself
with an `SSH-` banner.

---

## Usage

```text
device-discovery [options]

  --threads N              Worker threads for probing (default 32)
  --ssh-user USER          SSH username (default root)
  --ssh-password PASS      SSH password (visible in the process list;
                           prefer --ssh-password-env)
  --ssh-password-env VAR   Environment variable holding the password
                           (default DEVICE_SSH_PASSWORD, used when
                           --ssh-password is not given)
  --json                   Machine readable output
  --verbose                Diagnostic output on stderr
  --timeout MS             TCP connect timeout (default 750)
  --banner-timeout MS      SSH banner read timeout (default 1000)
  --auth-timeout MS        SSH authentication timeout (default 5000)
  --command-timeout MS     Remote command timeout (default 5000)
  --layer2-window MS       Layer-2 listening window (default 4000)
  --interface NAME         Disambiguate between candidate adapters
                           (Windows adapter name, e.g. "Ethernet 2")
  --select IP              Pick a candidate when several SSH devices answer
  --strict-host-key        Abort on unknown/mismatching SSH host keys
  --mock-ifconfig FILE     Offline mode: parse FILE as ifconfig output
  -h, --help               Show this help
```

There is deliberately no `--subnet` and no `--target-ip`.

### Example: successful run

```console
C:\> device-discovery.exe
Directly connected device discovered

SSH endpoint:
  IP:       192.168.10.50
  Banner:   SSH-2.0-OpenSSH_9.6
  Via:      Ethernet 2 (subnet-scan)
  Host key: unknown

Network interfaces:
  eth0    192.168.10.50
  eth1    10.20.30.1
```

```console
C:\> device-discovery.exe --json
{
  "ssh_ip": "192.168.10.50",
  "ssh_banner": "SSH-2.0-OpenSSH_9.6",
  "local_interface": "Ethernet 2",
  "discovery_stage": "subnet-scan",
  "host_key_status": "unknown",
  "interfaces": [
    {
      "name": "eth0",
      "ipv4": "192.168.10.50"
    },
    {
      "name": "eth1",
      "ipv4": "10.20.30.1"
    }
  ],
  "warnings": []
}
```

### Example: failure output

```console
C:\> device-discovery.exe
Error: Multiple candidate interfaces found; refusing to guess.
       Ethernet 2 192.168.10.20/24
       Wi-Fi 10.0.0.31/24
       Disconnect the unrelated links or pass --interface NAME.

C:\> device-discovery.exe --verbose
Error: No device discovered on Ethernet 2.
       the directly connected device was seen on the link but no SSH server could be reached at:
         10.20.30.1 (00:0c:29:4a:1b:36)
       If the address is outside 192.168.10.20/24 the PC has no route to it; add a temporary
       address on the device's subnet, e.g. netsh interface ipv4 add address "Ethernet 2"
       <free-ip> <netmask>

C:\> device-discovery.exe
Error: SSH authentication failed for user 'root'

C:\> device-discovery.exe --mock-ifconfig samples\ifconfig_net_tools.txt
Network interfaces:
  eth0    192.168.10.50
  eth1    10.20.30.1
```

### Exit codes

| Code | Meaning                                            |
| ---- | -------------------------------------------------- |
| 0    | success                                            |
| 2    | usage error / password not configured              |
| 3    | no suitable network interface found                |
| 4    | multiple candidate interfaces found                |
| 5    | no device discovered                               |
| 6    | multiple SSH devices discovered                    |
| 7    | SSH connection failed                              |
| 8    | SSH authentication failed                          |
| 9    | `ifconfig` (and the fallback) failed on the target |
| 10   | could not parse network interfaces                 |
| 11   | interfaces parsed, but the count is not two        |

---

## Multiple discovered devices

The physical setup guarantees a single device. If several SSH servers answer,
the tool lists all of them with their banners, prints
`WARNING: multiple SSH devices discovered`, and refuses to authenticate. Use
`--select IP` to choose one explicitly.

---

## Offline / mock mode

`--mock-ifconfig FILE` runs the parsing and output pipeline against captured
command output, so the end-to-end formatting can be exercised without a physical
device. Sample captures live in `samples/`.

---

## Troubleshooting

| Symptom                                     | Cause / remedy                                                                          |
| ------------------------------------------- | --------------------------------------------------------------------------------------- |
| `No suitable network interface found.`      | Cable unplugged (adapter shows "Network cable unplugged") or no IPv4 address yet — wait for DHCP/APIPA. |
| `Multiple candidate interfaces found.`      | Disable Wi-Fi/other links or pass `--interface "Ethernet 2"`.                             |
| `forbidden by its access permissions` in stage B | Re-run from an **Administrator** command prompt; `SIO_RCVALL` needs elevation.       |
| Device seen on the link but unreachable     | Static IP in a foreign subnet: `netsh interface ipv4 add address "Ethernet 2" <free-ip> <netmask>`. |
| Stage A finds nothing on a `/16` or larger  | Windows APIPA gives 169.254.0.0/16; subnets larger than `/22` are skipped by design, stage B takes over. |
| Windows Firewall                            | Outbound TCP/22 must be allowed for `device-discovery.exe`.                               |
| `port 22 is open but does not identify as SSH` | Something else listens on 22 on that host.                                              |
| `SSH authentication failed`                 | Wrong password/user; check `--ssh-password`/`DEVICE_SSH_PASSWORD` and `--ssh-user`.                        |
| Scan feels slow                             | Increase `--threads`, lower `--timeout`.                                                  |

---

## Security notes

* Credentials are never hard-coded, never logged and never printed — not even in
  error messages.
* Nothing is transmitted before the peer identified itself as an SSH server.
* Discovery is restricted to the single directly connected interface; no
  arbitrary networks are scanned and stage A refuses subnets larger than `/22`.
* Concurrency is bounded by the fixed-size thread pool (default 32 workers).
* Every network operation has a timeout (`src/config.hpp`).
* Banners received from the network are sanitised before being printed, so a
  hostile peer cannot inject terminal control sequences.

---

## Layout

```text
src/
├── main.cpp                      CLI, orchestration, exit codes
├── config.hpp                    all defaults/timeouts and exit codes
├── platform/windows_sockets.*    Winsock bootstrap and socket helpers
├── network/interface_discovery.* GetAdaptersAddresses-based adapter selection
├── network/arp_discovery.*       SIO_RCVALL capture + GetIpNetTable2 neighbour cache
├── scanner/port_scanner.*        non-blocking connect() with WSAPoll() timeout
├── scanner/ssh_detector.*        SSH banner read and validation
├── scanner/subnet_sweep.*        subnet enumeration + thread-pool sweep
├── ssh/ssh_client.*              libssh2 session, auth, remote command
├── parser/ifconfig_parser.*      ifconfig / ip -4 addr parsing
├── threading/thread_pool.*       fixed-size pool, futures, clean shutdown
└── output/formatter.*            text and JSON reports
tests/                            unit tests (ctest)
samples/                          captured command output for offline testing
```
