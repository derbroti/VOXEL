# About

This repository contains the source code as well as the scripts required to build a *VOXEL*-enabled server and client, and stream videos from the server to the client using VOXEL.

Please cite this work as follows (or use this [bibtex record](./bibtex.txt)).

  > Palmer, M., Appel, M., Spiteri, K., Chandrasekaran, B., Feldmann, A., and Sitaraman, R. K. VOXEL: Cross-layer Optimization for Video Streaming with Imperfect Transmission. In Proceedings of the 17th International Conference on Emerging Networking EXperiments and Technologies (2021), CoNEXT ’21.


The implementation is based on the sample QUIC server and client implementations provided as part of the [Chromium project](https://www.chromium.org/). To save space, this repository *only* contains the files modified from the Chromium codebase (in the `net` folder). The `prepare.sh` scripts performs the
first-time setup and downloads the remaining code.

Both the server and client are *headless* implementations: The video is, hence, written to disk during the stream and can be inspected afterwards.

The artifacts are organized as follows.

```
.
├── README.md
├── bandwidth-traces      # » Network traces used for experiments
├── generate-certs.sh     # » Utility to generate server certificates
├── make.sh               # » Invokes Chromium build tool
├── net                   # » Modified files from Chromium codebase
├── ninja-files           # » Patches to Chromium build files
├── prepare.sh            # » Fetches artifacts from Chromium and runs initial build
├── run-client.sh         # » Runs the client
├── run-server.sh         # » Runs the server
└── update-mod-links.sh   # » Links files in `net` with Chromium codebase
```


## Requirements

We built and tested the (client and server) implementations on an Ubuntu 20.04.3 (Focal Fossa) system. The implementations should work, in principle, on other Linux distributions, albeit some minor modifications may be required.

### System requirements

The Chromium codebase requires a non-trivial amount of disk space (*at least 60 GB*) and system memory (*at least 8 GB of RAM*, although *4 GB of RAM and another 4 GB swap* might also work) during the build process.

#### Hardware

To replicate *VOXEL*—the full end-to-end system—three separate machines (a client, a server, and a traffic-*shaper*) are required. In our testbed, we provided the shaper machine with two network interfaces and used these interfaces to connect it (via direct physical connections) to both the client and server machines. We placed the client-shaper and shaper-server interfaces in different subnets. Then, we bridged the two interfaces and configured the host to forward IP traffic.

This repository only includes, however, scripts for a simplified, local layout without a traffic shaper. We provide, nevertheless, the network trace files (in the `bandwidth-traces` directory) to reproduce our testbed setup, as described above.

### Package dependencies

The following packages are required for building the system and generating certificates. Install  them manually or via `apt-get`.

```
git python binutils libnss3-tools
```

All other additional dependencies are included in the Chromium codebase.

### Video files

We provide links to video files that have been preprocessed and ready to be streamed with VOXEL. We also provide manifest files to experiment with various features of VOXEL. You can retrieve the video files at the following URL.

    https://nextcloud.mpi-inf.mpg.de/index.php/s/e8e3C977wg2Kkty

The Chromium server code additionally requires the videos to include an HTTP response header.


## Building VOXEL

Run the `prepare.sh` script. This script *should* handle everything from downloading the code to building the system. The script adapts the [build procedure in the Chromium codebase](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/docs/linux/build_instructions.md) to suit our needs.

> *This codebase is almost 30 GB in size, and this setup can take a long time (over an hour) to build depending on the system configuration.*


## Generate & install certificates

Run the `generate-certs.sh` script. The script is an adaptation of [this](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/docs/linux/cert_management.md) procedure.

  > **This script will generate a CA certificate which is added to the root certificate store**, and the default lifetime of these certificates is only three days.
  
If you want to use the code for a longer time, either increase the validity period by modifying the `-days` parameters in `chrome/src/net/tools/quic/certs/generate-certs.sh`, and/or rerun `./generate-certs.sh`.

## Run the system

To run the system, start the server first, then (optionally) the traffic shaper, and, finally, the client.

The bandwidth trace files, in the `bandwidth-traces` directory, contain two columns: the first corresponds to the time in seconds since the start of the trace, and the second to the number of bytes transferred during the last second. In other words, each line corresponds to a bytes-per-second value. Feeding such a file line by line to `tc`, updating the available throughout each time, replays the network trace.

The system uses port `6121` by default, though the choice can be modified by changing the `PORT` variables in the run (i.e., `run-<client/server>.sh`) scripts.

### Start the server

Start the server with the `run-server.sh` script by providing it a path to a video directory.

```
» ./run-server.sh
usage: ./run-server.sh <path/to/video/dir>
```

Suppose the video files and manifests are organized as follows.

```
.
├── cache-bbb
└── www.example.org
    └── slipstream-bbb.mpd
```

Then the video directory path provided to the server *MUST* point to the *parent* folder containing the `www.example.org` directory, in the example above.

  > Do **not** use relative paths containing `..`, since the server executable ignores them. There will also be no error messages if a non-existing directory is specified.

After starting the server, **wait until** the message `Server Ready!` is displayed. The video files are loaded into RAM, which can take a few seconds.

### Start the client

Start the client with the `run-client.sh` script. The script requires the name of the MPD file that should be requested and the names of the output log and video files. The output files will be created, or overwritten, if they already exist.
```
» ./run-client.sh
usage: ./run-client.sh <MPD> <log-output> <video-output>
```


The output video is in the MP4 format, so it is preferable to specify an output with a `.mp4` extension, as follows.

```
» ./run-client.sh slipstream-bbb.mpd bbb-download.log bbb.mp4
```

This release only supports the VOXEL (`bpp`) ABR. The default (playback) buffer size is set to 8 seconds (one 4-second segment in buffer, and another in flight), but these values can be modified by adjusting the `BUF_SIZE_MS` variable in the script.

## Modifying the code

If you modify any of the source files in the `net` folder, rebuild the binaries by running the `make.sh` script. If any new modified files are added from the `chrome/src/net/` folder to the `net/` folder, re-run the `update-mod-links.sh` script once.
