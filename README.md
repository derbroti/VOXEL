## Repository structure

To save space, this repository only contains the modified files from the
Chromium codebase (`net` folder). The `prepare.sh` scripts performs the
first-time setup and downloads the remaining code.

## Requirements

The following setup was tested on a fresh Ubuntu 20.04.3 system, but should work
in principle on other Linux distributions (some modifications may be required).

### System requirements

The Chromium codebase requires a decent amount of disk space and system memory
during the build process:

  - At least 60 GB of free disk space
  - At least 8 GB of RAM (4 GB + 4 GB swap might also work)

### Packet dependencies

The following packets are required to build the system and to generate
certificates (`libnss3-tools`). All additional dependencies are included in the
Chromium codebase.

```
git python binutils libnss3-tools
```

## Build

Run the `prepare.sh` script. This *should* handle everything from downloading
the code to building the system. The steps are a modification from
[this](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/docs/linux/build_instructions.md)
process, adjusted for our system.

**Note: The codebase is almost 30 GB in size and this setup can take a long time
(over an hour) depending on the system.**

## Generate & install certificates

Run the `generate-certs.sh` script. **This will generate a CA certificate which
is added to the root certificate store.** The process is adapted from
[here](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/docs/linux/cert_management.md).

**Note:** The default lifetime of these certificates is only three days. If you
want to use the code for a longer time, either increase the validity period by
modifying the `-days` parameters in
`chrome/src/net/tools/quic/certs/generate-certs.sh`, and/or rerun
`./generate-certs.sh`.

## Run the system

To run the system, first start the server, optionally a traffic shaper (not
included in this repository), and then the client.

The bandwidth traces used in the experiments are included in the
`bandwidth-traces` folder, but we provide no traffic shaper script here. The
trace files contain two columns, the first corresponds to the time in seconds
since the start of the trace, the second to the number of bytes transferred
during the last second. In other words, each line corresponds to a bytes per
second value.

The default port used by the system is `6121` and can be modified by changing
the `PORT` variables in the run scripts.

### Start the server

Start the server with the `run-server.sh` script. This script requires a path to
a video directory.

**Note:** The video directory path must point to the *parent* folder containing
the `www.example.org` folder. For example, if the folder structure looks like

```
cache-bbb/www.example.org/slipstream-bbb.mpd
```

the run script should be called as

```
./run-server.sh cache-bbb
```

**Wait until the message `Server Ready!` is displayed. The video files are
loaded into RAM, which can take a few seconds.**

### Start the client

Start the client with the `run-client.sh` script. The script requires the name
of the MPD file that should be requested and the names of the output files to
which the log and the video will be written. These files will be created or
overwritten if they already exist.

**Note:** The output video is in the MP4 format, so specifying an output with
`.mp4` file ending makes sense.

Example:

```
./run-client.sh slipstream-bbb.mpd bbb-download.log bbb.mp4
```

The only supported ABR in this release is VOXEL (`bpp`). The default buffer size
in the script is 8 seconds (One segment in buffer, one segment in-flight) and
can be modified by adjusting the `BUF_SIZE_MS` variable.

## Modifying the code

If any of the code in the `net` folder was modified, the binaries can be rebuilt
by running the `make.sh` script.

If any new modified files are added from the `chrome/src/net/` folder to the
`net/` folder, the `update-mod-links.sh` script needs to be rerun once.
