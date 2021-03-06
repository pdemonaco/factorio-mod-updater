This module will automatically update all mods installed for a given instance of Factorio.

Note that this is primarily intended for headless dedicated Linux servers.

## Features

* Updates mods to the latest release based on mod-list.json
* Removes all old versions of mods which are being updated
* Limits releases to those compatible with the installed factorio version
* Installs all required dependencies for the latest release of the currently enabled mods

## Installation

1. Ensure a python3 implementation is available via something like `command -v python3`. If it's missing here's a few potential installation routes:
    
    **Ubuntu/Debian**
    ```bash
    sudo apt install python3 -y
    ```
    
    **RedHat Family (Fedora/CentOS/etc)**
    ```bash
    sudo yum install python36u -y
    ```

    **Gentoo**
    ```bash
    # Shouldn't be necessary since you'll have python for portage
    emerge -vt python
    ```
2. [Install requests](https://requests.readthedocs.io/en/master/user/install/#install) as described in their documentation. Or, on gentoo:

    ```bash
    emerge -vt dev-python/requests
    ```
3. Download the latest release and you should be good to go.

## Usage

Two modes are supported:

* `--list` - lists all mods described by mod-list.json, their current version, and the latest release
* `--update` - performs an update of all mods for the current server

Here's a brief example of executing the command:

```bash
./mod_updater.py -s /opt/factorio/data/server-settings.json \
  -m /opt/factorio/mods \
  --fact-path /opt/factorio/bin/x64/factorio --update
```

## Contributing

A few notes about the code:

* This script is designed to work with Python 3. Although there will be effort to avoid needlessly bumping the required version of Python 3, changes to make the script work on end-of-life versions of Python 3 are not supported.
* To ensure consistency in the code, format with `black` before submitting pull requests. You can install black with `pip install black` and then run `black mod_updater.py` in the repo to autoformat.
* On a best-effort basis, the script should pass all lints on `flake8` and `pylint`. You can also install these via pip and can run them with `flake8 mod_updater.py` and `pylint mod_updater.py` respectively.

## See Also

* [Ruby Factorio Mod Updater](https://github.com/astevens/factorio-mod-updater)
* [Factorio Server Updater](https://github.com/narc0tiq/factorio-updater)
* [Factorio Init Script](https://github.com/Bisa/factorio-init)
