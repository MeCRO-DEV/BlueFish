#!/bin/bash
if [ "server" = $1 ];
then
    echo -n "Installing server ... ..."
    cp -f bdserver.conf /etc
    cp -f server/server /usr/bin
    cp -f guard.sh /usr/bin
    chmod 777 /usr/bin/server
    chmod 777 /usr/bin/guard.sh
    echo "Done!"
    exit
fi
if [ "client" = $1 ];
then
    echo -n "Installing client ... ..."
    cp -f bdclient.conf /etc
    cp -f client/client /usr/bin
    chmod 777 /usr/bin/client
    echo "Done!"
    exit
fi
echo "Usage: $0 <server | client>"
