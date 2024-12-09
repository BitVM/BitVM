# Regtest Convenience Scripts

These scripts are provided to easily run an esplora regtest client via docker for local testing.

## Usage

### Installing

To automatically download the esplora docker image and configure the data directory, run:

```console
# ./install.sh
```

### Starting

To start the esplora client in regtest mode and automatically mine blocks, run:

```console
# ./start.sh
```

### Stopping

To stop the esplora client and stop mining blocks, run:

```console
# ./stop.sh
```

### Uninstalling

To uninstall everything, simply delete the data directory or run:

```console
# data_path=$(<data_path)
# rm -rf $data_path
# rm data_path
```