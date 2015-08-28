#!/bin/bash
#
# Usage: ./pipe2wireshark.sh CHANNEL
#
# If you get a USB permission error, please copy 99-cc2531-sniffer.rules to
# /etc/udev/rules.d and reload udev or reboot.
#
# $ cp 99-cc2531-sniffer.rules /etc/udev/rules.d
# $ sudo udevadm control --reload-rules
# $ # otherwise reboot
# $ sudo reboot

# get channel or set default
CHANNEL=$1
if [ -z "$CHANNEL" ]; then
    CHANNEL=26
fi

# start the sniffer and fork in background
python ccsniffpiper.py -c $CHANNEL -d &
SNIFFER_PID=$!

# wait and check if it's still running (e.g. permission error)
sleep 0.2
if ! ps -p $SNIFFER_PID &> /dev/null; then
    exit 1
fi

# install trap to kill sniffer when wireshark exits
trap 'kill $SNIFFER_PID' EXIT

# start wireshark immediately
wireshark -k -i /tmp/ccsniffpiper
