#!/usr/bin/python3
"""
This module provides a simple method to manage updating and installing mods
on a given factorio server.

It is currently not intended to be imported and instead should be executed
directly as a python script.
"""
import argparse
from collections import OrderedDict
from datetime import datetime, timezone
from enum import Enum, auto
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

# External URL processing library
# http://docs.python-requests.org/en/master/user/quickstart/
import requests


def _validate_hash(checksum: str, target: str, bsize: int = 65536) -> bool:
    """
    Checks to see if the file specified by target matches the provided sha1
    checksum.

    Keyword Arguments:
    checksum -- sha1 digest to be matched
    target   -- path to the file which must be validated
    """
    hasher = hashlib.sha1()

    with open(target, "rb") as target_fp:
        block = target_fp.read(bsize)
        while len(block) > 0:
            hasher.update(block)
            block = target_fp.read(bsize)

    return hasher.hexdigest() == checksum


def _version_match(installed: str, mod: str):
    """
    Checks if factorio versions are compatible.
    """
    version_regex = re.compile("(?P<major>\\d+)\\.(?P<minor>\\d+)(?:.(?P<sub>\\d+))?")
    mod_groups = version_regex.search(mod).groupdict()
    installed_groups = version_regex.search(installed).groupdict()
    if installed.startswith("1.") and mod.startswith("0.18"):
        return True
    if "sub" in mod_groups:
        return installed_groups == mod_groups
    return (
        installed_groups["major"] == mod_groups["major"]
        and installed_groups["minor"] == mod_groups["minor"]
    )


class ModUpdater:
    """
    Internal class managing the current version and state of the mods on this
    server.
    """

    MOD_VERSION_PATTERN = r"\d+[.]\d+[.]\d+"
    MOD_FILE_PATTERN = "^(.*)_({version})[.]zip$".format(version=MOD_VERSION_PATTERN)

    class Mode(Enum):
        """Possible execution modes"""

        LIST = auto()
        UPDATE = auto()

    def __init__(
        self,
        settings_path: str,
        data_path: str,
        mod_path: str,
        fact_path: str,
        creds: hash,
        title_mode: bool,
    ):
        """
        Initialize the updater class with all mandatory and optional arguments.

        Keyword arguments:
        settings_path -- absolute path to the server-settings.json file
        mod_path      -- absolute path to the factorio mod directory
        fact_ver      -- local factorio version
        """
        self.mod_server_url = "https://mods.factorio.com"
        self.mod_path = mod_path
        self.timestamp = datetime.now(timezone.utc)
        self.title_mode = title_mode

        # Get the credentials to download mods
        if settings_path is not None:
            self.settings = self._parse_settings(settings_path)
        else:
            self.settings = {}
        if data_path is not None:
            self.data = self._parse_settings(data_path)
        else:
            self.data = {}

        # Parse username and token
        if "username" in creds and creds["username"] is not None:
            self.username = creds["username"]
        elif "username" in self.settings:
            self.username = self.settings["username"]
        elif "service-username" in self.data:
            self.username = self.data["service-username"]
        else:
            self.token = None

        if "token" in creds and creds["token"] is not None:
            self.token = creds["token"]
        elif "token" in self.settings:
            self.token = self.settings["token"]
        elif "service-token" in self.data:
            self.token = self.data["service-token"]
        else:
            self.token = None

        # Ensure username and token were specified
        if self.username is None or self.username == "":
            errmsg = (
                "error: username not specified in "
                + "server-settings.json, player-data.json, or cli!"
            )
            print(errmsg, file=sys.stderr)
            sys.exit(1)

        if self.token is None or self.token == "":
            errmsg = (
                "error: token not specified in "
                + "server-settings.json, player-data.json, or cli!"
            )
            print(errmsg, file=sys.stderr)
            sys.exit(1)

        # Begin processing
        self._determine_version(fact_path)
        self._parse_mod_list()
        self._retrieve_metadata()
        self._determine_max_name_lengths()
        if self.title_mode:
            self.mods = OrderedDict(
                sorted(self.mods.items(), key=lambda mod: mod[1]["title"])
            )
        else:
            self.mods = OrderedDict(sorted(self.mods.items()))

    def _determine_version(self, fact_path: str):
        """Determine the local factorio version"""
        if not os.path.exists(fact_path):
            errmsg = "error: factorio binary '{fpath_path}' does not exist!"
            print(errmsg, file=sys.stderr)
            sys.exit(1)

        try:
            output = subprocess.check_output(
                [fact_path, "--version"], universal_newlines=True
            )
            ver_re = re.compile(r"Version: (\d+)[.](\d+)[.](\d+) .*\n", re.RegexFlag.M)
            match = ver_re.match(output)
            if match:
                version = {}
                version["major"] = match.group(1)
                version["minor"] = match.group(2)
                version["patch"] = match.group(3)
                version["release"] = "{}.{}".format(version["major"], version["minor"])
                self.fact_version = version
            else:
                errmsg = "Unable to parse version from:\n{output}".format(output=output)
                print(errmsg, file=sys.stderr)
                sys.exit("1")

        except subprocess.CalledProcessError as error:
            errmsg = ("error: failed to run  '{fpath} --version': " "{errstr}").format(
                fpath=fact_path, errstr=error.stderr
            )
            print(errmsg, file=sys.stderr)
            sys.exit(1)

        print(
            "Factorio Release: {release}\n".format(release=self.fact_version["release"])
        )

    @staticmethod
    def _parse_settings(config_path: str):
        """Process the specified server-settings.json or player-data.json file."""
        try:
            with open(config_path, "r") as config_fp:
                return json.load(config_fp)
        except IOError as error:
            errmsg = ("error: failed to open file '{fname}': " "{errstr}").format(
                fname=config_path, errstr=error.strerror
            )
            print(errmsg, file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as error:
            errmsg = ("error: failed to parse json file '{fname}': " "{errstr}").format(
                fname=config_path, errstr=error.msg
            )
            print(errmsg, file=sys.stderr)
            sys.exit(1)

    def _retrieve_metadata(self):
        """
        Pull the latest metadata for each mod from the factorio server
        See https://wiki.factorio.com/Mod_portal_API for details
        """
        print("Retrieving metadata", end="")
        for mod, data in self.mods.items():
            self._retrieve_mod_metadata(mod)
            print(".", end="", flush=True)
        print("complete!\n")

        # Add missing dependencies to the overall list
        while True:
            missing_mods = []
            for mod, data in self.mods.items():
                if "missing_deps" in data:
                    missing_mods.extend(data["missing_deps"])

            unique_missing = set(missing_mods)
            for mod in self.mods.keys():
                if mod in unique_missing:
                    unique_missing.remove(mod)
            if len(unique_missing) == 0:
                break
            for mod in unique_missing:
                entry = {}
                entry["enabled"] = True
                entry["installed"] = False
                self.mods[mod] = entry
                self._retrieve_mod_metadata(mod)
                print("Info: adding missing dependency {dep}".format(dep=mod))

        for mod, data in self.mods.items():
            if "metadata" not in data:
                warnmsg = (
                    "Warning: Unable to retrieve metadata for"
                    " {mod}, skipped!".format(mod=mod)
                )
                print(warnmsg)

    def _retrieve_mod_metadata(self, mod: str):
        """
        Attempts to retrieve the metadata for the target mod. If found, the
        data object is updated with the 'metadata' key and the 'latest' keys.
        """
        data = self.mods[mod]
        mod_url = self.mod_server_url + "/api/mods/" + mod + "/full"
        with requests.get(mod_url) as req:
            if req.status_code == 200:
                data["metadata"] = req.json()

        if "metadata" in data:
            # Find the latest release for this version of Factorio
            matching_releases = []
            for rel in data["metadata"]["releases"]:
                rel_ver = rel["info_json"]["factorio_version"]
                if _version_match(installed=self.fact_version["release"], mod=rel_ver):
                    matching_releases.append(rel)

            if len(matching_releases) > 0:
                data["latest"] = matching_releases[-1]

            # Add title key
            data["title"] = data["metadata"]["title"]

            # Mark whether it's deprecated
            data["deprecated"] = data["metadata"].get("deprecated", False)
        else:
            data["title"] = mod

            # Assume not deprecated if we can't find it
            data["deprecated"] = False

        if "latest" in data:
            self._resolve_dependencies(mod)

    def _resolve_dependencies(self, mod: str):
        """
        Processes the dependency list for this mod and returns an array
        listing those which are not currently enabled. Note that this skips
        exclusions and optional dependencies. (! and ?)
        """
        data = self.mods[mod]
        if "latest" in data:
            data["missing_deps"] = []
            data["dependencies"] = {}
            dependencies = data["latest"]["info_json"]["dependencies"]
            # Preparation for future explicit version matching
            dep_pattern = re.compile(
                r"^(?:~ )?(?P<name>[\w -]+)(?: (?P<arg>(?:[<>]=?)|=) \
                        (?P<ver>\d+[.]\d+[.]\d+))?$"
            )
            for dep_entry in dependencies:
                match = dep_pattern.fullmatch(dep_entry)
                if match:
                    dep = {}
                    dep_name = match.group("name")
                    if dep_name == "base":
                        continue
                    dep["argument"] = match.group("arg")
                    dep["version"] = match.group("ver")
                    data["dependencies"][match.group(1)] = dep

            for dep_name in data["dependencies"].keys():
                if dep_name not in self.mods:
                    data["missing_deps"].append(dep_name)

    def _parse_mod_list(self):
        """Process the mod-list.json within mod_path."""
        mod_list_path = os.path.join(self.mod_path, "mod-list.json")
        try:
            settings_fp = open(mod_list_path, "r")
            mod_json = json.load(settings_fp)
            self.mods = {}
            if "mods" in mod_json:
                for mod in mod_json["mods"]:
                    entry = {}
                    entry["enabled"] = mod["enabled"]
                    self.mods[mod["name"]] = entry
            else:
                print(
                    "Invalid mod-list.json file \
                      '{path}'!".format(
                        path=mod_list_path
                    ),
                    file=sys.stderr,
                )
                sys.exit(1)

            # Remove the 'base' mod as it's not relevant to this process
            if "base" in self.mods:
                del self.mods["base"]
        except IOError as error:
            errmsg = ("error: failed to open file '{fname}': " "{errstr}").format(
                fname=mod_list_path, errstr=error.strerror
            )
            print(errmsg, file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as error:
            errmsg = ("error: failed to parse json file '{fname}': " "{errstr}").format(
                fname=mod_list_path, errstr=error.msg
            )
            print(errmsg, file=sys.stderr)
            sys.exit(1)

        # Collect the installed state & versions
        self.mod_files = glob.glob("{mod_path}/*.zip".format(mod_path=self.mod_path))
        installed_mods = {}
        mod_pattern = re.compile(self.MOD_FILE_PATTERN)
        for entry in self.mod_files:
            basename = os.path.basename(entry)
            match = mod_pattern.fullmatch(basename)
            if match:
                installed_mods[match.group(1)] = match.group(2)

        for mod, data in self.mods.items():
            if mod in installed_mods:
                data["installed"] = True
                data["version"] = installed_mods[mod]
            else:
                data["installed"] = False

    def _update_mod_list(self):
        """
        Generates an updated mod-list.json file which takes into account any
        newly added dependencies.
        """
        # Build the simplified object for json output
        mod_list_output = {}
        mod_list_output["mods"] = []
        for mod, data in self.mods.items():
            mod_entry = {}
            mod_entry["name"] = mod
            mod_entry["enabled"] = data["enabled"]
            mod_list_output["mods"].append(mod_entry)

        # Rename the old mod-list file with a timestamp
        mod_list_path = os.path.join(self.mod_path, "mod-list.json")
        mod_list_backup_path = os.path.join(
            self.mod_path,
            "mod-list.{timestamp}.json".format(
                timestamp=self.timestamp.strftime("%Y-%m-%d_%H%M.%S")
            ),
        )
        try:
            os.rename(src=mod_list_path, dst=mod_list_backup_path)
        except IOError as error:
            errmsg = (
                "error: failed to rename file '{s}' to '{d}': " "{errstr}"
            ).format(s=mod_list_path, d=mod_list_backup_path, errstr=error.strerror)
            print(errmsg, file=sys.stderr)
            sys.exit(1)

        # Store the current mod list
        try:
            mod_list_fp = open(mod_list_path, "w")
            mod_list_fp.write(json.dumps(mod_list_output, indent=2, sort_keys=True))
        except IOError as error:
            errmsg = (
                "error: failed to store updated mod list file '{s}': " "{errstr}"
            ).format(s=mod_list_path, errstr=error.strerror)
            print(errmsg, file=sys.stderr)
            sys.exit(1)

    def _determine_max_name_lengths(self):
        """Returns the length of the longest mod name"""
        max_mod_len = 0
        max_cver_len = 0
        max_lver_len = 0
        for mod, data in self.mods.items():
            mod_len = len(data["title"]) if self.title_mode else len(mod)
            max_mod_len = mod_len if mod_len > max_mod_len else max_mod_len
            cver_len = len(data["version"]) if data["installed"] else len("Version")
            max_cver_len = cver_len if cver_len > max_cver_len else max_cver_len
            lver_len = (
                len(data["latest"]["version"]) if "latest" in data else len("Version")
            )
            max_lver_len = lver_len if lver_len > max_lver_len else max_lver_len

        self.max_mod_len = max_mod_len
        self.max_cver_len = max_cver_len
        self.max_lver_len = max_lver_len
        self.max_ver_len = max_lver_len if max_lver_len > max_cver_len else max_cver_len

    def list(self):
        """Lists the mods installed on this server."""
        # Find the longest mod name

        print(
            "{:<{width}}\tenabled\tinstalled\tcurrent_v\tlatest_v".format(
                "mod_name", width=self.max_mod_len
            )
        )
        for mod, data in self.mods.items():
            print(
                "{:<{width}}\t{enbld}\t{inst}\t\t{cver}\t\t{lver}".format(
                    mod,
                    enbld=str(data["enabled"]),
                    inst=str(data["installed"]),
                    cver=data["version"] if data["installed"] else "N/A",
                    lver=data["latest"]["version"] if "latest" in data else "N/A",
                    width=self.max_mod_len,
                )
            )

    def override_credentials(self, username: str, token: str):
        """Replaces the values provided in server-settings.json or player-data.json"""
        if username is not None:
            self.username = username
        if token is not None:
            self.token = token

    def _print_mod_message(
        self, mod: str, version: str, action: str, result: str, message: str, data: hash
    ):
        """
        Prints a mod status message using the provided parameters.
        """
        if data is not None:
            title = data["title"] if self.title_mode else mod
        else:
            title = mod

        output_string = (
            "{title:<{mwidth}}\t{version:<{vwidth}}"
            "\t{action:<10}\t{result:<10}\t{message}"
        ).format(
            title=title,
            version=version,
            action=action,
            result=result,
            message=message,
            vwidth=self.max_ver_len,
            mwidth=self.max_mod_len,
        )
        print(output_string)

    def update(self):
        """
        Updates all mods currently installed on this server to the latest
        release
        """
        self._print_mod_message("Mod", "Version", "Action", "Result", "Message", None)

        for mod, data in self.mods.items():
            version = data["version"] if data["installed"] else "N/A"
            if "metadata" not in data:
                self._print_mod_message(
                    mod=mod,
                    version=version,
                    action="Skip",
                    result="N/A",
                    message="Missing metadata, skipping update!",
                    data=data,
                )
                continue
            if "latest" not in data:
                message = (
                    "No release found for factorio '{version}', skipping update!"
                ).format(version=self.fact_version["release"])
                self._print_mod_message(
                    mod=mod,
                    version=version,
                    action="Skip",
                    result="N/A",
                    message=message,
                    data=data,
                )
                continue

            self._prune_old_releases(mod)
            self._download_latest_release(mod)

        # Update the mod list file
        self._update_mod_list()

    def _prune_old_releases(self, mod: str):
        """
        Deletes any locally installed versions older than the latest release.

        Keyword Arguments:
        mod -- name of the target to update
        """
        data = self.mods[mod]
        latest_version = data["latest"]["version"]

        # Declare the patterns
        mod_pattern = re.compile(
            "^{mod}_({ver})[.]zip$".format(mod=mod, ver=self.MOD_VERSION_PATTERN)
        )
        version_pattern = re.compile(
            "^{mod}_{ver}[.]zip$".format(mod=mod, ver=latest_version)
        )

        # Build the parse list
        basenames = [os.path.basename(x) for x in self.mod_files]
        inst_rels = [x for x in basenames if mod_pattern.fullmatch(x)]
        for rel in inst_rels:
            if version_pattern.fullmatch(rel):
                continue

            match = mod_pattern.fullmatch(rel)
            if match:
                rel_ver = match.group(1)
            else:
                rel_ver = "TBD"

            rel_path = os.path.join(self.mod_path, rel)
            try:
                os.remove(rel_path)
                result = "Success"
                message = ""
            except OSError as error:
                message = ("error: failed to remove '{fname}': " "{errstr}").format(
                    fname=rel_path, errstr=error.strerror
                )
                result = "Failure"

            self._print_mod_message(
                mod=mod,
                version=rel_ver,
                action="Remove",
                result=result,
                message=message,
                data=data,
            )

    def _download_latest_release(self, mod: str):
        """
        Retrieves the latest version of the specified mod compatible with the
        factorio release present on this server.

        Keyword Arguments:
        mod -- name of the target to update
        """
        data = self.mods[mod]
        latest = data["latest"]
        target = os.path.join(self.mod_path, latest["file_name"])

        validate = download = False

        v_cur = data["version"] if "version" in data else "N/A"
        v_new = latest["version"]
        if data["installed"]:
            if v_new == v_cur:
                validate = True
            else:
                message = "Updating from '{v_cur}'".format(v_cur=v_cur)
                download = True
        else:
            message = "Downloading initial release '{v_new}'".format(v_new=v_new)
            download = True

        if validate:
            if _validate_hash(latest["sha1"], target):
                result = "Success"
                message = "Deprecated mod" if data["deprecated"] else ""
            else:
                result = "Failure"
                download = True
                message = "Validation failed, downloading again"
            self._print_mod_message(
                mod=mod,
                version=v_cur,
                action="Validate",
                result=result,
                message=message,
                data=data,
            )

        if download:
            creds = {"username": self.username, "token": self.token}
            dl_url = self.mod_server_url + latest["download_url"]
            with requests.get(dl_url, params=creds, stream=True) as req:
                if req.status_code == 200:
                    with open(target, "wb") as target_file:
                        shutil.copyfileobj(req.raw, target_file)
                        target_file.flush()
                    if _validate_hash(latest["sha1"], target):
                        result = "Success"
                    else:
                        result = "Failure"
                        message = "Download did not match checksum!"
                elif req.status_code == 403:
                    message = (
                        "Failed to download, credentials not accepted. "
                        + "Check your username/token"
                    )
                    result = "Failure"
                else:
                    message = "Unable to retrieve, status code: " + str(req.status_code)
                    result = "Failure"

            self._print_mod_message(
                mod=mod,
                version=v_new,
                action="Download",
                result=result,
                message=message,
                data=data,
            )


if __name__ == "__main__":
    DESC_TEXT = "Updates mods for a target factorio installation"
    PARSER = argparse.ArgumentParser(description=DESC_TEXT)
    # Username
    PARSER.add_argument(
        "-u",
        "--username",
        dest="username",
        help="factorio.com username overriding server-settings.json/player-data.json",
    )
    # Token
    PARSER.add_argument(
        "-t",
        "--token",
        dest="token",
        help="factorio.com API token overriding server-settings.json/player-data.json",
    )
    # Title format
    PARSER.add_argument(
        "--print-titles",
        dest="title_mode",
        default=False,
        action="store_true",
        help="When true, print the mod title instead of the api name",
    )
    # Server Settings
    PARSER.add_argument(
        "-s",
        "--server-settings",
        dest="settings_path",
        required=False,
        help=(
            "Absolute path to the server-settings.json file "
            + "(overrides player-data.json)"
        ),
    )
    # Player Data
    PARSER.add_argument(
        "-d",
        "--player-data",
        dest="data_path",
        required=False,
        help="Absolute path to the player-data.json file",
    )
    # Factorio mod directory
    PARSER.add_argument(
        "-m",
        "--mod-directory",
        dest="mod_path",
        required=True,
        help="Absolute path to the mod directory",
    )
    # Factorio binary absolute path
    PARSER.add_argument(
        "--fact-path",
        dest="fact_path",
        required=True,
        help="Absolute path to the factorio binary",
    )
    # Possible Execution modes
    MODE_GROUP = PARSER.add_mutually_exclusive_group(required=True)
    MODE_GROUP.add_argument(
        "--list",
        dest="mode",
        action="store_const",
        const=ModUpdater.Mode.LIST,
        help="List the currently installed mods with versions",
    )
    MODE_GROUP.add_argument(
        "--update",
        dest="mode",
        action="store_const",
        const=ModUpdater.Mode.UPDATE,
        help="Update all mods to their latest release",
    )

    ARGS = PARSER.parse_args()
    UPDATER = ModUpdater(
        settings_path=ARGS.settings_path,
        data_path=ARGS.data_path,
        mod_path=ARGS.mod_path,
        fact_path=ARGS.fact_path,
        creds={"username": ARGS.username, "token": ARGS.token},
        title_mode=ARGS.title_mode,
    )

    if ARGS.mode == ModUpdater.Mode.LIST:
        UPDATER.list()
    elif ARGS.mode == ModUpdater.Mode.UPDATE:
        UPDATER.update()
