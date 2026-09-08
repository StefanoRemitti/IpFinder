# device-discovery

C++17 command line utility that discovers the Linux device connected directly to
this PC, verifies its SSH endpoint, authenticates over SSH and reports the IPv4
addresses of the device's two network interfaces.

The user never supplies a subnet, an interface or a target IP:

```bash
DEVICE_SSH_PASSWORD='root' ./device-discovery
```

---

## Physical setup

```text
PC Ethernet interface (DHCP)
        |
        | direct Ethernet cable, no other stations on the link
        |
Target Linux device (static IP, sshd on TCP/22, two interfaces)
```

---

## Build

Required system packages:

| Distribution   | Packages                                          |
| -------------- | ------------------------------------------------- |
| Debian/Ubuntu  | `build-essential cmake pkg-config libssh2-1-dev`   |
| Fedora/RHEL    | `gcc-c++ cmake pkgconf-pkg-config libssh2-devel`   |
| Arch           | `base-devel cmake libssh2`                         |

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Artefacts: `build/device-discovery` plus the unit test binaries.

---

## How discovery works

### 1. Local interface selection (`src/network/interface_discovery.cpp`)

Interfaces are enumerated with `getifaddrs(3)` (no shelling out to `ifconfig` or
`ip`). An interface becomes a *candidate* only when all of the following hold:

* it is **not** loopback (`IFF_LOOPBACK`),
* it is administratively up (`IFF_UP`) **and** operationally running
  (`IFF_RUNNING`, i.e. carrier present),
* it has an IPv4 address **and** a netmask,
* its name is not a well-known virtual interface
  (`docker*`, `veth*`, `br-*`, `virbr*`, `tun*`, `tap*`, `wg*`, `bond*`,
  `dummy*`, `vboxnet*`, `vmnet*`, `zt*`, `tailscale*`, …).

If **no** candidate remains the tool exits with `No suitable network interface
found.` If **several** candidates remain it lists them and exits rather than
silently guessing; `--interface NAME` can be used to disambiguate.

### 2. Stage A — directly connected IPv4 subnet (`src/scanner/`)

From the selected interface the tool computes the network address, the broadcast
address and every host address of the directly connected subnet, excluding the
network address, the broadcast address and the PC's own address. Subnets larger
than `/22` (more than 1022 hosts) are refused so the tool never sweeps an
unbounded range; discovery then falls straight through to stage B.

Every address is probed through the fixed-size thread pool:

1. non-blocking `connect()` to TCP/22 with `poll()` and a 750 ms timeout,
2. read of the peer's identification string with a 1000 ms timeout,
3. the address only counts as a target when the identification **starts with
   `SSH-`** — an open port alone is never sufficient.

### 3. Stage B — static IP outside the DHCP subnet (`src/network/arp_discovery.cpp`)

Because the PC uses DHCP while the target uses a static address, the target may
live outside the PC's subnet. If stage A finds nothing, layer-2 discovery is
performed and is strictly limited to the directly connected link:

1. the kernel neighbour cache (`/proc/net/arp`) is read for that interface,
2. an `AF_PACKET`/`SOCK_RAW` socket is bound to that interface only,
3. a broadcast ARP announcement for the PC's own address is emitted to encourage
   the peer to speak,
4. for the duration of the listening window (default 4000 ms) every ARP frame
   (sender protocol address) and every IPv4 frame (source address) originating
   from another station is recorded.

No address outside the observed link is ever probed, and no arbitrary
private/Internet range is scanned. Layer-2 observation and TCP/SSH verification
are separate steps: each observed address is afterwards verified with the same
`SSH-` banner check as stage A.

`AF_PACKET` requires `CAP_NET_RAW`. Without it the tool reports the reason
explicitly:

```text
Error: No device discovered on enp3s0.
       cannot open AF_PACKET socket on enp3s0: Operation not permitted (layer-2
       discovery needs root or CAP_NET_RAW: sudo setcap cap_net_raw+ep ./device-discovery)
```

If a station is seen on the link but its address is not routable from the PC
(static IP in a foreign subnet), the diagnostic names the observed address, MAC
and the remedy (temporarily adding an address on that subnet) instead of
claiming that no device exists.

### 4. SSH authentication and remote command (`src/ssh/ssh_client.cpp`)

libssh2 is used — the SSH protocol is never re-implemented. The client
authenticates with username (default `root`) and the password taken from an
environment variable, runs `ifconfig` first (part of the device contract) and
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

```bash
DEVICE_SSH_PASSWORD='root' ./device-discovery
# or with a different variable
MY_SECRET='…' ./device-discovery --ssh-password-env MY_SECRET
```

Reading the password from the environment (or from a file exported into the
environment, e.g. `set -a; . /etc/device-discovery.env; set +a` with mode `0600`)
is preferred over a command line flag because command line arguments are visible
to every user through `/proc`.

### Host-key verification

Host-key verification is **configurable and, by default, non-fatal**:

* default (`Warn`): the key is compared against `~/.ssh/known_hosts`; an unknown
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
  --ssh-password-env VAR   Environment variable holding the password
                           (default DEVICE_SSH_PASSWORD)
  --json                   Machine readable output
  --verbose                Diagnostic output on stderr
  --timeout MS             TCP connect timeout (default 750)
  --banner-timeout MS      SSH banner read timeout (default 1000)
  --auth-timeout MS        SSH authentication timeout (default 5000)
  --command-timeout MS     Remote command timeout (default 5000)
  --layer2-window MS       Layer-2 listening window (default 4000)
  --interface NAME         Disambiguate between candidate interfaces
  --select IP              Pick a candidate when several SSH devices answer
  --strict-host-key        Abort on unknown/mismatching SSH host keys
  --mock-ifconfig FILE     Offline mode: parse FILE as ifconfig output
  -h, --help               Show this help
```

There is deliberately no `--subnet` and no `--target-ip`.

### Example: successful run

```console
$ DEVICE_SSH_PASSWORD='root' ./device-discovery
Directly connected device discovered

SSH endpoint:
  IP:       192.168.10.50
  Banner:   SSH-2.0-OpenSSH_9.6
  Via:      enp3s0 (subnet-scan)
  Host key: unknown

Network interfaces:
  eth0    192.168.10.50
  eth1    10.20.30.1
```

```console
$ DEVICE_SSH_PASSWORD='root' ./device-discovery --json
{
  "ssh_ip": "192.168.10.50",
  "ssh_banner": "SSH-2.0-OpenSSH_9.6",
  "local_interface": "enp3s0",
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
$ DEVICE_SSH_PASSWORD='root' ./device-discovery
Error: Multiple candidate interfaces found; refusing to guess.
       enp3s0 192.168.10.20/24
       wlp2s0 10.0.0.31/24
       Disconnect the unrelated links or pass --interface NAME.

$ DEVICE_SSH_PASSWORD='root' ./device-discovery --verbose
Error: No device discovered on enp3s0.
       the directly connected device was seen on the link but no SSH server could be reached at:
         10.20.30.1 (00:0c:29:4a:1b:36)
       If the address is outside 192.168.10.20/24 the PC has no route to it; add a temporary
       address on the device's subnet, e.g. sudo ip addr add <free-ip>/<prefix> dev enp3s0

$ DEVICE_SSH_PASSWORD='wrong' ./device-discovery
Error: SSH authentication failed for user 'root'

$ ./device-discovery --mock-ifconfig samples/ifconfig_net_tools.txt
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
| `No suitable network interface found.`      | Cable unplugged (no carrier) or the interface has no IPv4 address yet — wait for DHCP.    |
| `Multiple candidate interfaces found.`      | Disable Wi-Fi/other links or pass `--interface NAME`.                                     |
| `Operation not permitted` in stage B        | `sudo setcap cap_net_raw+ep ./build/device-discovery` (or run with `sudo`).                |
| Device seen on the link but unreachable     | Static IP in a foreign subnet: `sudo ip addr add <free-ip>/<prefix> dev <iface>`.          |
| `port 22 is open but does not identify as SSH` | Something else listens on 22 on that host.                                              |
| `SSH authentication failed`                 | Wrong password/user; check `DEVICE_SSH_PASSWORD` and `--ssh-user`.                        |
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
├── network/interface_discovery.* getifaddrs-based interface selection
├── network/arp_discovery.*       AF_PACKET layer-2 discovery + /proc/net/arp
├── scanner/port_scanner.*        non-blocking connect() with poll() timeout
├── scanner/ssh_detector.*        SSH banner read and validation
├── scanner/subnet_sweep.*        subnet enumeration + thread-pool sweep
├── ssh/ssh_client.*              libssh2 session, auth, remote command
├── parser/ifconfig_parser.*      ifconfig / ip -4 addr parsing
├── threading/thread_pool.*       fixed-size pool, futures, clean shutdown
└── output/formatter.*            text and JSON reports
tests/                            unit tests (ctest)
samples/                          captured command output for offline testing
```
