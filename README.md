# VOXEL

This repository provides the files and scripts required to build a VOXEL-enabled
server and client and perform a simple video stream.

The system is based on the sample QUIC server and client implementations
provided as part of the [Chromium project](https://www.chromium.org/). Both the
server and client are headless implementations so the video is written to disk
during the stream and can be inspected afterwards.

## Repository structure

To save space, this repository only contains the modified files from the
Chromium codebase (`net` folder). The `prepare.sh` scripts performs the
first-time setup and downloads the remaining code.

The network traces used for the experiments are located in the
`bandwidth-traces` folder.

## Requirements

The following setup was tested on a fresh Ubuntu 20.04.3 system, but should work
in principle on other Linux distributions (some modifications may be required).

### System requirements

The Chromium codebase requires a decent amount of disk space and system memory
during the build process:

  - At least 60 GB of free disk space
  - At least 8 GB of RAM (4 GB + 4 GB swap might also work)

#### Hardware

To replicate the full end-to-end system, three separate machines (client,
server, traffic-shaper) are required. The traffic-shapher, in our testbed, 
has a direct physical network connection to the client 
and server, and, thus, needs to have two network interfaces.

The connections client-shaper and shaper-server are placed in different subnets.
The shaper interfaces are bridged and the host is configured to forward ip traffic.

This repository only includes scripts
for a simplified, local layout without a traffic shaper. However, the network
traces are provided to enable the full replication of the system, albeit with
additional effort.

### Package dependencies

The following packages are required to build the system and to generate
certificates (`libnss3-tools`). All additional dependencies are included in the
Chromium codebase.

```
git python binutils libnss3-tools
```
### Video files

We provide links to video files already prepared to be streamed with VOXEL.
The Chromium server code requires the videos to include an HTTP response header.
Additionally, to be able to utilize all VOXEL features, prepared manifest files are provided as well.

You can find the video files here: https://nextcloud.mpi-inf.mpg.de/index.php/s/e8e3C977wg2Kkty.

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

To run the system, first start the server, optionally a traffic shaper, and
then the client.

The bandwidth traces used in the experiments are included in the
`bandwidth-traces` folder. The trace files contain two columns, the first
corresponds to the time in seconds since the start of the trace, the second to
the number of bytes transferred during the last second. In other words, each
line corresponds to a bytes-per-second value. Feeding this file line by line to `tc`, 
updating the available throughout each time, with a one per second, replays the network trace. 

The default port used by the system is `6121` and can be modified by changing
the `PORT` variables in the run scripts.

### Start the server

Start the server with the `run-server.sh` script. This script requires a path to
a video directory.

The video directory path must point to the *parent* folder containing the
`www.example.org` folder. For example, if the folder structure looks like

```
cache-bbb/www.example.org/slipstream-bbb.mpd
```

the run script should be called as

```
./run-server.sh cache-bbb
```

**Note:** Do **not** use relative paths containing `..`, since the server
executable ignores them and there is no error message if a non-existing
directory is specified.

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

