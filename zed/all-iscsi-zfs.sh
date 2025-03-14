#!/usr/bin/env bash

set -euf -o pipefail

case "${ZEVENT_CLASS}" in
  sysevent.fs.zfs.pool_export)
    /usr/bin/iscsi-zfs deactivate "${ZEVENT_POOL}"
    ;;
  sysevent.fs.zfs.pool_import)
    /usr/bin/iscsi-zfs activate "${ZEVENT_POOL}"
    ;;
  sysevent.fs.zfs.history_event)
    if [[ "${ZEVENT_HISTORY_INTERNAL_NAME}" == "set" ]] && [[ "${ZEVENT_HISTORY_INTERNAL_STR}" =~ "iscsi:" ]]; then
      /usr/bin/iscsi-zfs reload "${ZEVENT_POOL}" "${ZEVENT_HISTORY_DSNAME}"
    fi
    ;;
  *)
    ;;
esac