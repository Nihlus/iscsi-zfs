iscsi-zfs
=========

`iscsi-zfs` is an addon to the ZFS filesystem, enabling export of ZFS volumes as
iSCSI targets based on ZFS properties. 

# iSCSI ZFS User Properties

This document describes the supported user properties that control generation of 
iSCSI targets from a ZFS volume. Each volume can only be part of a single iSCSI 
target, but multiple volumes can be associated with the same iSCSI target as
separate LUNs.

All properties are grouped under the `iscsi` ZFS property module.

| Property                 | Type   | Required                | Description                                                                                             | Default                                                         |
|--------------------------|--------|-------------------------|---------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| `iscsi:share`            | `bool` | no                      | Indicates whether the volume should be shared as part of an iSCSI target                                | `off`                                                           |
| `iscsi:target`           | `str`  | no                      | The name of the iSCSI target to associate the volume with                                               | `iqn.YYYY-MM.<reverse-hostname>:zfs-`[`name-slug`](#name-slugs) |
| `iscsi:lun`              | `int`  | no                      | The ID of the LUN to attach the volume as. If the ID is already taken, the next free ID is used instead | 0                                                               |
| `iscsi:acls`             | `str`  | no                      | A semicolon-separated list of ACL entries to add to the target                                          | (unset)                                                         |
| `iscsi:chap`             | `bool` | no                      | Indicates whether to use CHAP authentication for the target                                             | `on`                                                            |
| `iscsi:chap_credentials` | `str`  | yes, if `iscsi:chap=on` | A path to a file with the username and password to use for CHAP authentication                          | /usr/local/etc/iscsi-zfs/chap.conf                              |
| `iscsi:portals`          | `str`  | no                      | A list of network portals in `address:port` format                                                      | `0.0.0.0:3260`                                                  |

## Name Slugs
Generally, if you do not specify an explicit value for names, one will be 
generated for you based on a typical string slugging scheme. For example, if you 
have a ZVOL at `tank/images/my-volume`, the generated iSCSI target will look
something like `iqn.2023-12.org.example.myhost:zfs-tank-images-my-volume`.

## Lists
Some properties are lists of values. Since ZFS does not natively support 
multi-value properties, a semicolon is used as a value separator.

## Authentication
By default, the program generates targets that require CHAP authentication
without ACLs. You can disable CHAP and use ACLs only, or leave the ACL field
empty to allow anyone to access the target. This is obviously an unsafe
configuration which should only be used in trusted environments, and even then
only if no other option is available.