#!/usr/bin/env python3

from __future__ import annotations

import configparser
import logging
import os
import os.path
import re
import stat
import sys
from argparse import ArgumentParser, Namespace
from datetime import datetime
from functools import cached_property
from itertools import groupby
from pathlib import Path
from platform import node
from typing import Iterator, Tuple, Iterable

import coloredlogs
from filelock import FileLock
from libzfs import ZFS, ZFSPool, ZFSDataset, DatasetType, ZFS_PROPERTY_CONVERTERS, ZfsConverter
from rtslib import NetworkPortal
from rtslib_fb import RTSRoot, BlockStorageObject, Target, LUN, TPG
from rtslib_fb.fabric import ISCSIFabricModule
from slugify import slugify

# native properties missing from the library
ZFS_PROPERTY_CONVERTERS["guid"] = ZfsConverter(int, readonly=True)

# our custom properties that need some extra configuration
ZFS_PROPERTY_CONVERTERS["iscsi:share"] = ZfsConverter(bool)
ZFS_PROPERTY_CONVERTERS["iscsi:lun"] = ZfsConverter(int)
ZFS_PROPERTY_CONVERTERS["iscsi:chap"] = ZfsConverter(bool)


class IQN:
    """
    Represents an iSCSI Qualified Name, composed of sub-elements that uniquely identify the iSCSI resource within the
    scope of the authority's control.

    :ivar year: The year when the resource was defined.
    :ivar month: The month when the resource was defined.
    :ivar authority: The authority within which the resource is guaranteed to be uniquely represented.
    :ivar unique_name: The unique name of the resource.
    """

    _authority_regex = re.compile("^[a-zA-Z0-9.-]+$")
    """
    Holds a regular expression used for simple validity checks of IQN authority names.
    """

    def __init__(self, year: int, month: int, authority: str, unique_name: str) -> None:
        """
        Initializes a new instance of the IQN class.

        :param year: The year when the resource was defined.
        :param month: The month when the resource was defined.
        :param authority: The authority within which the resource is guaranteed to be uniquely represented.
        :param unique_name: The unique name of the resource.
        """

        if month not in range(1, 12 + 1):
            raise ValueError(f"{month} is not a valid month")

        if not IQN._authority_regex.match(authority):
            raise ValueError(f"\"{authority}\" is not a valid iSCSI authority (should be reversed domain name)")

        self.year = year
        self.month = month
        self.authority = authority
        self.unique_name = unique_name

    def __str__(self) -> str:
        """
        Converts the instance to its string representation.

        :return: The string representation of the IQN.
        """
        return f"iqn.{self.year:04}-{self.month:02}.{self.authority}:{self.unique_name}"

    @staticmethod
    def parse(value: str) -> IQN:
        """
        Parses the given string as an IQN.

        :param value: The string to parse.
        :return: The parsed IQN.
        :raises ValueError: Raised when some component of the input string is not valid as part of an IQN.
        """

        selector_parts = value.split(":", maxsplit=2)
        if len(selector_parts) != 2:
            raise ValueError

        iqn_parts = selector_parts[0].split(".")
        if iqn_parts[0] != "iqn":
            raise ValueError

        date_parts = iqn_parts[1].split('-')
        if len(date_parts) != 2:
            raise ValueError

        year = int(date_parts[0])
        month = int(date_parts[1])

        authority = ".".join(iqn_parts[2:])
        unique_name = selector_parts[1]

        return IQN(year, month, authority, unique_name)


class ZFSiSCSIVolume:
    """
    Represents information about an iSCSI-enabled ZFS volume.

    iSCSI-related properties are post-filled by the application and are not part of the object's own initialization.

    :ivar volume: The ZFS volume to which the iSCSI information belongs.
    :ivar enabled: Whether the volume is enabled and should be considered during target configuration.
    :ivar iscsi_backstore: The block storage object associated the volume.
    :ivar iscsi_target: The iSCSI target to which the volume belongs.
    :ivar iscsi_lun: The iSCSI Logical Unit to which the volume belongs.
    :ivar iscsi_tpg: The iSCSI Target Portal Group to which the volume's LUN belongs.
    :ivar iscsi_portals: The iSCSI Network Portals to which the volume's LUN belongs.
    """

    def __init__(self, volume: ZFSDataset, enabled: bool):
        """
        Initializes a new instance of the ZFSiSCSIVolume class.

        :param volume: The ZFS volume to which the iSCSI information belongs.
        """

        self.volume = volume
        self.enabled = enabled

        self.iscsi_backstore: BlockStorageObject | None = None
        self.iscsi_target: Target | None = None
        self.iscsi_lun: LUN | None = None
        self.iscsi_tpg: TPG | None = None
        self.iscsi_portals: list[NetworkPortal] | None = None

    def __str__(self) -> str:
        """
        Converts the instance to its string representation.

        :return: The name of the ZFS volume.
        """
        return self.volume.name

    @cached_property
    def device(self) -> Path:
        """
        Gets the filesystem path to the device node of the ZFS volume.

        :return: The path.
        """
        return (Path("/") / "dev" / "zvol" / self.volume.name).absolute()

    @cached_property
    def target_iqn(self) -> IQN:
        """
        Gets the IQN of the iSCSI target the volume belongs to. The target can be explicitly set via the
        ``iscsi:target`` ZFS property. If the property is not set, a default target unique to this volume is used.

        :return: The IQN.
        """

        explicit_target = self.volume.properties.get("iscsi:target")
        if not explicit_target:
            return self._default_target_name

        return IQN.parse(explicit_target.value)

    @cached_property
    def lun(self) -> int:
        """
        Gets the LUN number the volume should be exposed as in the iSCSI target. The LUN number can be explicitly set
        via the ``iscsi:lun`` ZFS property. If the property is not set, the LUN number defaults to 0.

        :return: The LUN number.
        """
        iscsi_lun = self.volume.properties.get("iscsi:lun")
        if not iscsi_lun:
            return 0

        return iscsi_lun.parsed

    @cached_property
    def acls(self) -> list[str]:
        """
        Gets a list of the iSCSI initiators allowed to access the volume (iSCSI ACLs). The ACLs can be explicitly set
        via the ``iscsi:acls`` ZFS property as a comma-separated list. If the property is not set, the resulting list
        will be empty.

        :return: The ACLs, if any.
        """

        iscsi_acls = self.volume.properties.get("iscsi:acls")
        if not iscsi_acls:
            return []

        return [acl for acl in iscsi_acls.value.split(";") if acl]

    @cached_property
    def use_chap(self) -> bool:
        """
        Gets a value indicating whether CHAP (Challenge Handshake Authentication Protocol) should be used for the iSCSI
        target associated with the volume. This value can be explicitly set via the ``iscsi:chap`` ZFS property. If the
        property is not set, CHAP is enabled by default.

        If multiple volumes in an iSCSI target disagree on whether to enable CHAP, the volume(s) who want CHAP "win" and
        CHAP is enabled.

        :return: True if CHAP should be enabled; otherwise, false.
        """

        iscsi_chap = self.volume.properties.get("iscsi:chap")
        if not iscsi_chap:
            return True

        return iscsi_chap.parsed

    @cached_property
    def chap_credentials(self) -> Path:
        """
        Gets a filesystem path to a file containing the CHAP (Challenge Handshake Authentication Protocol) credentials
        to use for the iSCSI target associated with the volume. This value can be explicitly set via the
        ``iscsi:chap_credentials`` ZFS property. If the property is not set, the path defaults to
        ``/etc/iscsi-zfs/chap.conf``.

        :return: The path to the credentials file.
        """

        # explicit property comes first
        iscsi_chap_credentials = self.volume.properties.get("iscsi:chap_credentials")
        if iscsi_chap_credentials:
            return Path(iscsi_chap_credentials.value)

        # fall back to system-level default configuration
        return Path("/") / "etc" / "iscsi-zfs" / "chap.conf"

    @cached_property
    def wwn(self) -> str:
        """
        Gets the vendor-assigned component of the iSCSI WWN (World-Wide Name) that the volume's backing block storage
        should have. iSCSI typically uses a Format 6 Address for its WWNs, giving us 100 bits of vendor-assigned data to
        play with.

        The structure of a Format 6 Address is as follows::

            +---+-------+---------------+-------------------------+
            |NAA|  OUI  |Vendor Assigned|Vendor Assigned Extension|
            +---+-------+---------------+-------------------------+
            4-bit 24-bit  36-bit          64-bit

        In our case, we use the ZFS GUIDs of the pool and the dataset to form our unique identifier. We assign the first
        36 bits of the pool's GUID to the Vendor Assigned data, and the entire dataset GUID to the Vendor Assigned
        Extension. Therefore, a WWN created by this program is structured as follows::

            +---+-------+---------------+-------------------------+
            |NAA|  OUI  | ZFS Pool GUID |     ZFS Dataset GUID    |
            +---+-------+---------------+-------------------------+
            4-bit 24-bit  36-bit          64-bit

        :return: The WWN.
        """

        # special handling: a ZFS GUID is a 64-bit random number, which needs some massaging to get a "real" hexadecimal
        # string out of.
        pool_guid = '{:016x}'.format(self.volume.pool.guid & ((1 << 64) - 1))
        dataset_guid = '{:016x}'.format(self.guid & ((1 << 64) - 1))

        return f"{pool_guid[0:9]}{dataset_guid}"

    @cached_property
    def backstore_name(self) -> str:
        """
        Gets the name used for the iSCSI block device backstore.

        :return: The name.
        """
        volume_name = os.path.basename(self.volume.name)
        return f"iscsi-zfs:{slugify(volume_name)}-{self.wwn}"

    @cached_property
    def portals(self) -> list[Tuple[str, int]]:
        """
        Gets the portals configured for the iSCSI target.

        :return: The portals, as pairs of IP addresses and port numbers.
        """

        iscsi_portals = self.volume.properties.get("iscsi:portals")

        raw_portals = "0.0.0.0:3260" if not iscsi_portals else iscsi_portals.value
        return [
            (address, int(port)) for (address, port) in [
                raw_portal.split(":") for raw_portal in raw_portals.split(";")
            ]
        ]

    @cached_property
    def created_at(self) -> datetime:
        """
        Gets the time at which the dataset was created.

        :return: The time.
        """

        creation = self.volume.properties.get("creation")
        return creation.parsed

    @cached_property
    def guid(self) -> int:
        """
        Gets the ZFS GUID of the dataset. Note that a ZFS GUID is not the same as what most people understand a GUID to
        be; rather, it is represented as a 64-bit unsigned integer and is typically presented as a raw numeric value.
        Due to Python's design, the value returned here is a two's-complement signed integer and needs to be
        post-processed if any representation changes are required.

        :return: The GUID.
        """

        guid = self.volume.properties.get("guid")
        return guid.parsed

    @cached_property
    def _default_target_name(self) -> IQN:
        """
        Gets the default iSCSI target name of the volume. This value is used if no target name is explicitly set, and is
        unique for this volume.

        :return: The default target IQN.
        """

        year = self.created_at.year
        month = self.created_at.month

        node_name = node()
        node_name = '.'.join(reversed(node_name.split('.')))

        volume_slug = slugify(self.volume.name)
        return IQN(year, month, node_name, "zfs-" + volume_slug)


class CHAPCredentials:
    """
    Represents a set of CHAP credentials.

    :ivar username: The CHAP username.
    :ivar password: The CHAP password.
    """

    def __init__(self, username: str, password: str) -> None:
        """
        Initializes a new instance of the CHAPCredentials class.

        :param username: The username.
        :param password: The password.
        """

        self.username = username
        self.password = password

    @staticmethod
    def load_from(path: Path) -> CHAPCredentials:
        """
        Loads CHAP credentials from the given on-disk file.

        :param path: The path to the file with the credentials.
        :return: The credentials.
        """

        file_status = os.stat(path)
        file_mode = file_status.st_mode

        if (
            stat.S_IRGRP & file_mode or
            stat.S_IROTH & file_mode or
            stat.S_IWGRP & file_mode or
            stat.S_IWOTH & file_mode
        ):
            logging.warning(
                f"insecure file permissions on {path} - only the owner of the "
                f"file should have read and write permissions"
            )

        config = configparser.ConfigParser()
        config.read(path)

        return CHAPCredentials(config['CHAP']['Username'], config['CHAP']['Password'])


class Program:
    """
    Defines the main program logic.
    """

    def __init__(self) -> None:
        """
        Initializes a new instance of the Program class.
        """

        self._zfs = ZFS()
        self._rts_root = RTSRoot()
        self._iscsi_module = ISCSIFabricModule()
        self._credential_cache: dict[Path, CHAPCredentials] = {}

        coloredlogs.install()

    def reload(self, pool_name: str, dataset_name: str | None) -> int:
        """
        Reloads the ZFS-based iSCSI configuration for the given pool (and optionally a specific dataset), deactivating
        and then activating all applicable targets.

        :param pool_name: The name of the pool to operate on.
        :param dataset_name: The name of the dataset to operate on. Defaults to all datasets.
        :return: The return code of the program.
        """

        return_code = self.deactivate(pool_name, dataset_name)
        if return_code:
            return return_code

        return_code = self.activate(pool_name, dataset_name)
        if return_code:
            return return_code

        return 0

    def activate(self, pool_name: str, dataset_name: str | None) -> int:
        """
        Activates ZFS-based iSCSI configuration, creating, updating, or deleting targets and backstores as
        required.

        :param pool_name: The name of the pool to operate on.
        :param dataset_name: The name of the dataset to operate on. Defaults to all datasets.
        :return: The return code of the program.
        """

        # save the current configuration so that it can be restored if we fail for any reason
        current_config = self._rts_root.dump()

        try:
            logging.info("scanning for iSCSI configuration")
            # pick out the enabled volumes only, ignoring the rest
            iscsi_volumes = [volume for volume in self._get_zfs_iscsi_volumes(pool_name) if volume.enabled]

            if dataset_name:
                # determine the iqn
                dataset_volume = next((volume for volume in iscsi_volumes if volume.volume.name == dataset_name), None)

                if not dataset_volume:
                    logging.error(f"dataset {dataset_name} not found")
                    return 1

                dataset_iqn = dataset_volume.target_iqn

                # find all volumes that belong to the iqn
                iscsi_volumes = [volume for volume in iscsi_volumes if volume.target_iqn == dataset_iqn]

            self._configure_targets(pool_name, iscsi_volumes)
        except Exception as e:
            logging.exception(e)

            # oops, unexpected failure - restore the previous config
            self._rts_root.restore(current_config, clear_existing=True)
            return 1

        return 0

    def deactivate(self, pool_name: str, dataset_name: str | None) -> int:
        """
        Deactivates ZFS-based iSCSI targets and backstores, removing them from the configuration.

        :param pool_name: The name of the pool to operate on.
        :param dataset_name: The name of the dataset to operate on. Defaults to all datasets.
        :return: The return code of the program.
        """

        # save the current configuration so that it can be restored if we fail for any reason
        current_config = self._rts_root.dump()

        try:
            logging.info("deactivating iSCSI configuration")
            targets = self._get_managed_targets(pool_name)

            if dataset_name:
                iscsi_volumes = self._get_zfs_iscsi_volumes(pool_name)

                # determine target name of the dataset
                dataset_volume = next((volume for volume in iscsi_volumes if volume.volume.name == dataset_name), None)

                if not dataset_volume:
                    logging.error(f"dataset {dataset_name} not found")
                    return 1

                target_iqn = dataset_volume.target_iqn

                dataset_target = next((target for target in targets if target.wwn == target_iqn), None)

                if not dataset_target:
                    logging.info(f"target {target_iqn} not found; nothing to do")
                    return 0

                targets = [dataset_target]

            self._remove_targets(targets, "deactivating")
        except Exception as e:
            logging.exception(e)

            # oops, unexpected failure - restore the previous config
            self._rts_root.restore(current_config, clear_existing=True)
            return 1

        return 0

    def _configure_targets(self, pool_name: str, volumes: list[ZFSiSCSIVolume]) -> None:
        """
        Configures iSCSI targets for the given set of iSCSI-enabled ZFS volumes.

        :param pool_name: The name of the pool to operate on.
        :param volumes: The iSCSI-enabled ZFS volumes.
        """

        self._configure_backstores(volumes)

        logging.info("configuring targets")

        # ensure all requested targets exist
        zfs_iscsi_targets: Iterator[Tuple[str, Iterable[ZFSiSCSIVolume]]] = groupby(
            sorted(volumes, key=lambda v: str(v.target_iqn)),
            lambda v: str(v.target_iqn)
        )

        valid_managed_targets = [
            self._configure_target(target_iqn, list(target_volumes)) for target_iqn, target_volumes in zfs_iscsi_targets
        ]

        logging.info("cleaning up")
        targets_to_remove = [
            target for target in self._get_managed_targets(pool_name)
            if target not in valid_managed_targets
        ]

        self._remove_targets(targets_to_remove, "no longer referenced")

    @staticmethod
    def _remove_targets(targets: Iterable[Target], reason: str) -> None:
        """
        Removes the given targets and their backstores from the configuration.

        :param targets: The targets.
        :param reason: The reason for the target's removal.
        """

        for target in targets:
            logging.info(f"deleting target {target.wwn} ({reason})")

            attached_storage: list[BlockStorageObject] = [
                lun.storage_object for tpg in target.tpgs for lun in tpg.luns
            ]

            target.delete()

            for storage_object in attached_storage:
                if any(storage_object.attached_luns):
                    # still in use by something else
                    continue

                logging.info(f"deleting backstore {storage_object.name} ({reason})")
                storage_object.delete()

    def _configure_backstores(self, volumes: list[ZFSiSCSIVolume]) -> None:
        """
        Configures iSCSI backstores for the given set of iSCSI-enabled ZFS volumes. Each volume will have one backstore
        mapped to it.

        :param volumes: The iSCSI-enabled ZFS volumes.
        """

        def get_backstores() -> Iterator[BlockStorageObject]:
            """
            Gets the block-based backstore objects from the iSCSI backend.

            :return: The storage objects.
            """
            return (block for block in self._rts_root.storage_objects if isinstance(block, BlockStorageObject))

        def find_managed_backstore(volume: ZFSiSCSIVolume) -> BlockStorageObject | None:
            """
            Searches for an existing backstore that matches the given ZFS volume. Backstore objects are matched based on
            the actual device node path (or udev path) or the managed name of the backstore.

            :param volume: The volume to search for a matching backstore for.
            :return: The backstore, or None if no matching backstore was found.
            """
            # TODO: what if we get more than one result here?
            return next(
                (
                    block
                    for block in get_backstores()
                    if Path(block.udev_path) == volume.device or block.name == volume.backstore_name
                ),
                None
            )

        def is_consistent(backstore: BlockStorageObject, volume: ZFSiSCSIVolume) -> bool:
            """
            Checks if the backstore's configuration is consistent with the given ZFS volume. Consistency, for the
            purposes of this check, means having a matching device path, object name, and WWN (World Wide Name).

            :param backstore: The backstore to check.
            :param volume: The ZFS volume.
            :return: True if the backstore's configuration is consistent with the volume; otherwise, False.
            """
            if Path(backstore.udev_path) != volume.device:
                return False

            if backstore.name != volume.backstore_name:
                return False

            if backstore.wwn != volume.wwn:
                return False

            return True

        logging.info("configuring backstores")

        # ensure all volumes have a block backstore
        for volume in volumes:
            managed_backstore = find_managed_backstore(volume)
            if managed_backstore and not is_consistent(managed_backstore, volume):
                # backstores can't really be edited after creation, so we'll have to delete it and recreate it
                logging.warning("found an existing backstore with mismatched data - deleting and recreating")

                managed_backstore.delete()
                managed_backstore = None

            if not managed_backstore:
                logging.info(f"creating backstore for {volume.volume.name} "
                             f"using device {str(volume.device)} "
                             f"with WWN {volume.wwn}")

                # create a new backstore for this volume
                managed_backstore = BlockStorageObject(
                    volume.backstore_name,
                    str(volume.device),
                    volume.wwn
                )

            volume.iscsi_backstore = managed_backstore

    def _configure_target(self, target_iqn: str, volumes: list[ZFSiSCSIVolume]) -> Target:
        """
        Configures an iSCSI target with the given IQN (iSCSI Qualified Name) and the given participating volumes. Each
        volume will be configured as a LUN in the target.

        :param target_iqn: The target IQN.
        :param volumes: The participating volumes.
        :return: The resulting target.
        """
        def find_managed_target(iqn: str, pool_name: str) -> Target | None:
            """
            Searches for an existing managed target with the given IQN (iSCSI Qualified Name). Whether a target is
            managed or not is determined via checking for a known pattern in the target's unique name.

            :param iqn: The IQN of the target to search for.
            :param pool_name: The name of the pool the target belongs to.
            :return: The target, or None if no matching target was found.
            """

            return next((target for target in self._get_managed_targets(pool_name) if target.wwn == iqn), None)

        def find_managed_tpg(target: Target) -> TPG | None:
            """
            Searches for an existing managed TPG (Target Portal Group) within the given target. Currently, the first TPG
            is always managed by this program, and all other TPGs are considered invalid.

            :param target: The target to search for the TPG in.
            :return: The TPG, or None if no matching TPG was found.
            """

            return next(target.tpgs, None)

        def find_managed_portals(tpg: TPG, volumes: list[ZFSiSCSIVolume]) -> list[NetworkPortal]:
            """
            Searches for managed Network Portals within the given TPG (Target Portal Group). Managed portals are
            identified by matching their addresses and ports to the ones configured on the iSCSI volume properties. If
            no particular portals are configured, a default portal of 0.0.0.0:3260 is assumed.

            :param tpg: The TPG to search for the portals in.
            :param volumes: The iSCSI volume configurations to refer to.
            :return: The portals, or an empty list if no matching portals was found.
            """

            return [
                portal for portal in tpg.network_portals
                if any(
                    volume_portal[0] == portal.ip_address and volume_portal[1] == portal.port
                    for volume in volumes
                    for volume_portal in volume.portals
                )
            ]

        def find_managed_lun(tpg: TPG, backstore: BlockStorageObject) -> LUN | None:
            """
            Searches for an existing managed LUN (Logical Unit) within the given TPG (Target Portal Group).

            :param tpg: The TPG to search for the LUN in.
            :param backstore: The backstore to match the LUN against.
            :return: The LUN, or None if no matching LUN was found.
            """

            return next((lun for lun in tpg.luns if lun.storage_object == backstore), None)

        def is_lun_consistent(lun: LUN, volume: ZFSiSCSIVolume) -> bool:
            """
            Determines whether the configuration of the given LUN (Logical Unit) is consistent with the given ZFS
            volume. Consistency, in this case, is determined by comparing the LUN number with the one requested by the
            ZFS volume.

            :param lun: The LUN to check the consistency of.
            :param volume: The ZFS volume to check consistency against.
            :return: True if the LUN is consistent with the volume; otherwise, false.
            """

            return lun.lun == volume.lun

        volume_names = ' ,'.join([iscsi_volume.volume.name for iscsi_volume in volumes])

        managed_target = find_managed_target(target_iqn, volumes[0].volume.pool.name)
        if not managed_target:
            logging.info(f"creating target {target_iqn} for {volume_names}")
            managed_target = Target(self._iscsi_module, target_iqn)

        managed_tpg = find_managed_tpg(managed_target)
        if not managed_tpg:
            managed_tpg = TPG(managed_target)
            managed_tpg.enable = True

        # clean out other TPGs
        _ = [tpg.delete() for tpg in managed_target.tpgs if tpg != managed_tpg]

        managed_portals = find_managed_portals(managed_tpg, volumes)
        for volume in volumes:
            for portal in volume.portals:
                if not any(
                    portal[0] == managed_portal.ip_address and portal[1] == managed_portal.port
                    for managed_portal in managed_portals
                ):
                    managed_portals.append(managed_tpg.network_portal(portal[0], portal[1]))

        # clean out other portals
        _ = [portal.delete() for portal in managed_tpg.network_portals if portal not in managed_portals]

        # configure portal ACLs
        acls = set([acl for volume in volumes for acl in volume.acls])
        managed_tpg.set_attribute("generate_node_acls", str(0 if any(acls) else 1))
        managed_tpg.set_attribute("demo_mode_write_protect", str(1 if any(acls) else 0))
        for acl in acls:
            managed_tpg.node_acl(acl)

        # clean out other ACLs
        _ = [acl.delete() for acl in managed_tpg.node_acls if acl.node_wwn not in acls]

        # configure portal authentication
        use_chap = any([volume.use_chap for volume in volumes])
        managed_tpg.set_attribute("authentication", str(1 if use_chap else 0))

        credentials_path = next((volume.chap_credentials for volume in volumes), None)
        if use_chap:
            if credentials_path.exists():
                credentials = self._get_chap_credentials(credentials_path)
                managed_tpg.chap_userid = credentials.username
                managed_tpg.chap_password = credentials.password
            else:
                logging.warning("No CHAP credentials available")

        for iscsi_volume in volumes:
            iscsi_volume.iscsi_target = managed_target
            iscsi_volume.iscsi_tpg = managed_tpg
            iscsi_volume.iscsi_portals = managed_portals

            managed_lun = find_managed_lun(managed_tpg, iscsi_volume.iscsi_backstore)
            if managed_lun and not is_lun_consistent(managed_lun, iscsi_volume):
                # LUNs can't really be edited after creation, so we'll have to delete it and recreate it
                logging.warning("found an existing LUN with mismatched data - deleting and recreating")

                managed_lun.delete()
                managed_lun = None

            if not managed_lun:
                managed_lun = iscsi_volume.iscsi_tpg.lun(iscsi_volume.lun, iscsi_volume.iscsi_backstore)

            iscsi_volume.iscsi_lun = managed_lun

        return managed_target

    def _get_chap_credentials(self, path: Path) -> CHAPCredentials:
        """
        Gets the CHAP credentials in the file at the given path, searching in an internal cache before loading the file
        from disk again.

        :param path: The path to the credentials file.
        :return: The CHAP credentials.
        """

        if path not in self._credential_cache:
            self._credential_cache[path] = CHAPCredentials.load_from(path)

        return self._credential_cache[path]

    def _get_managed_targets(self, pool_name: str) -> Iterator[Target]:
        """
        Gets an iterator over existing targets which are managed by this program.

        :return: The targets.
        """

        target_prefix = slugify(f"zfs-{pool_name}")
        return (
            target for target in self._rts_root.targets
            if IQN.parse(target.wwn).unique_name.startswith(target_prefix)
        )

    def _get_zfs_iscsi_volumes(self, pool_name: str) -> list[ZFSiSCSIVolume]:
        """
        Recursively searches the named ZFS pool for iSCSI-enabled ZFS volumes, loading their desired configuration into
        usable objects.

        :param pool_name: The name of the ZFS pool to scan.
        :return: The iSCSI-enabled ZFS volumes, if any.
        """

        def _get_parented_iscsi_volumes(parent: ZFSDataset) -> list[ZFSiSCSIVolume]:
            """
            Recursively searches the given ZFS dataset for iSCSI-enabled ZFS volumes, loading their desired
            configuration into usable objects.

            :param parent: The ZFS dataset to scan.
            :return: The iSCSI-enabled ZFS volumes, if any.
            """
            logging.debug(f"scanning {parent.name} for iSCSI-enabled volumes")

            volumes: list[ZFSiSCSIVolume] = []

            for dataset in parent.children:
                if dataset.type is not DatasetType.VOLUME:
                    volumes.extend(_get_parented_iscsi_volumes(dataset))
                    continue

                iscsi_share = dataset.properties.get("iscsi:share")
                if not iscsi_share.parsed:
                    continue

                logging.debug(f"found iSCSI configuration for {dataset.name}")
                volumes.append(ZFSiSCSIVolume(dataset, iscsi_share))

            return volumes

        pool: ZFSPool | None = next((pool for pool in self._zfs.pools if pool.name == pool_name), None)

        return _get_parented_iscsi_volumes(pool.root_dataset)


def activate(args: Namespace) -> int:
    return Program().activate(args.pool_name, args.dataset_name)


def deactivate(args: Namespace) -> int:
    return Program().deactivate(args.pool_name, args.dataset_name)


def reload(args: Namespace) -> int:
    return Program().reload(args.pool_name, args.dataset_name)


def main() -> int:
    parser = ArgumentParser(prog="iscsi-zfs", description="Controls ZFS-based iSCSI targets")
    subparsers = parser.add_subparsers(help="sub-command help")

    activate_parser = subparsers.add_parser("activate", help="activate help")
    activate_parser.add_argument('pool_name', help="The name of the pool to operate on")
    activate_parser.add_argument("dataset_name", required=False, default=None, help="The name of the dataset to operate on. Defaults to all datasets in the pool")
    activate_parser.set_defaults(func=activate)

    deactivate_parser = subparsers.add_parser("deactivate", help="deactivate help")
    deactivate_parser.add_argument('pool_name', help="The name of the pool to operate on")
    deactivate_parser.add_argument("dataset_name", required=False, default=None, help="The name of the dataset to operate on. Defaults to all datasets in the pool")
    deactivate_parser.set_defaults(func=deactivate)

    reload_parser = subparsers.add_parser("reload", help="reload help")
    reload_parser.add_argument('pool_name', help="The name of the pool to operate on")
    reload_parser.add_argument("dataset_name", required=False, default=None, help="The name of the dataset to operate on. Defaults to all datasets in the pool")
    reload_parser.set_defaults(func=reload)

    args = parser.parse_args(sys.argv[1:])

    # we use the same lockfile as targetcli, because we don't want step on each other's toes
    logging.info("acquiring lock")
    with FileLock("/var/run/targetcli.lock"):
        return args.func(args)


if __name__ == '__main__':
    main()
