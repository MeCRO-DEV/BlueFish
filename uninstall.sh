#!/bin/bash
if [ "server" = $1 ];
then
    echo -n "Uninstalling server ... ..."
    rm -f /etc/bdserver.conf
    rm -f /usr/bin/server
    rm -f /usr/bin/guard.sh
    echo "Done!"
    exit
fi
if [ "client" = $1 ];
then
    echo -n "Uninstalling client ... ..."
    rm -f /etc/bdclient.conf
    rm -f /usr/bin/client
    echo "Done!"
    exit
fi
echo "Usage: $0 <server | client>"
