#!/bin/sh
# 04_usb_data_theft.sh — MITRE T1052.001 Exfiltration over USB / T1025 Data from
#                        Removable Media
#
# REAL-LIFE STORY
#   Someone walks up to the machine, inserts a USB stick, copies sensitive
#   files onto it, and walks away. The forensic trace is in the kernel ring
#   buffer: usb-storage attach messages with vendor/product/serial, a new
#   block device, a mount, and file access times.
#
# WHY THIS ONE IS DIFFERENT — IT IS ONLY PARTLY AUTOMATABLE
#   You cannot script a physical insertion. This script therefore has two
#   parts: a MANUAL checklist you perform at the machine, and an automatic
#   part that (a) detects whether a removable device is now present, (b) copies
#   a lab marker file onto it if you point us at it, and (c) records ground
#   truth. Everything USB-side is GENUINE — real kernel messages, real device.
#
# DETECTION LAYER
#   EVIDENCE ONLY. The usb parser produces usb_connect/usb_disconnect timeline
#   events with duration + vendor/product; the storage parser adds the mount.
#   There is no dedicated USB *rule* today, so score_detection will not score
#   this — validate it with the SQL in the tickbox / the queries below.
#
# REPRODUCIBLE: PARTIALLY. The insertion is manual and needs a VM with USB
#   passthrough (VirtualBox/VMware) or bare metal — NOT WSL. The evidence it
#   produces is fully reproducible once a stick is inserted.

set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$DIR/lib.sh"
require_root "04_usb_data_theft"
confirm_lab

cat <<'MANUAL'
[*] MANUAL STEPS (do these physically, in order, THEN let this script finish):
    1. Note the current time (UTC):  date -u
    2. Insert a USB mass-storage device into the VM/host.
       - VirtualBox: Devices > USB > <your stick>.
       - VMware: VM > Removable Devices > <your stick> > Connect.
    3. Confirm the kernel saw it:    dmesg | tail -20   (look for 'usb-storage',
       'idVendor', 'Product', 'Attached SCSI removable disk').
    4. Mount it if not auto-mounted: lsblk ; mount /dev/sdX1 /mnt
    5. Copy sensitive-looking files onto it (or let this script drop a marker).
    6. Unmount + physically remove it:  umount /mnt   (records a disconnect +
       a connection DURATION, which is what the usb parser computes).
MANUAL

printf "Press Enter once the device is INSERTED and mounted (or Ctrl-C to abort)... "
[ "${LFA_LAB_CONFIRM:-}" = "yes" ] || read -r _

echo "[*] Removable devices currently visible to the kernel:"
REMOVABLE=""
for d in /sys/block/*; do
    name=$(basename "$d")
    if [ -f "$d/removable" ] && [ "$(cat "$d/removable" 2>/dev/null)" = "1" ]; then
        echo "    /dev/$name (removable)"
        REMOVABLE="$REMOVABLE $name"
    fi
done
[ -n "$REMOVABLE" ] || echo "    (none detected — is passthrough enabled? are you on WSL?)"

# Optional: drop a genuine marker file on a mountpoint the operator names.
if [ -n "${LFA_USB_MOUNT:-}" ] && [ -d "$LFA_USB_MOUNT" ]; then
    echo "[*] Writing lab marker to $LFA_USB_MOUNT ..."
    echo "LAB MARKER — synthetic exfil $(now_iso)" > "$LFA_USB_MOUNT/STOLEN_DATA.txt" || true
fi

echo "[*] Recent USB kernel messages (this is the evidence the parser reads):"
{ dmesg 2>/dev/null | grep -iE "usb-storage|idVendor|Product:|removable disk" | tail -15; } || \
  echo "    (dmesg not readable; the collector reads /var/log/kern.log|syslog instead)"

write_ground_truth "$DIR/04_usb_data_theft.ground_truth.json" \
  "usb_data_theft" \
  '[
    {"threat_id":"T1052_usb_insert","name":"Removable USB storage attached",
     "expected_rule":null,"detection_layer":"evidence",
     "details":"usb-storage attach with vendor/product/serial in kern.log",
     "verify":"SELECT * FROM events WHERE subcategory IN (\"usb_connect\",\"usb_disconnect\")"},
    {"threat_id":"T1025_removable_mount","name":"Removable device mounted",
     "expected_rule":null,"detection_layer":"evidence",
     "details":"new block device + mount recorded by the storage parser",
     "verify":"SELECT * FROM events WHERE subcategory=\"storage_device\""}
  ]'
echo "[+] Scenario 04 complete. Remember to UNMOUNT + REMOVE the stick to record a disconnect."
