# Linux

This directory contains Linux-only assets, scripts, and distributable artifacts.

The files inside `Linux/dist/` are meant to be publishable prebuilt artifacts.

## Setup

```bash
./Linux/scripts/setup_linux_venv.sh
```

## Run From Source

```bash
./Linux/scripts/run_linux_gui.sh
```

## Build

```bash
./Linux/scripts/build_linux_binary.sh
./Linux/scripts/build_linux_appimage.sh
```

The generated files in `Linux/dist/` can be committed and uploaded to GitHub releases or the repository itself.
