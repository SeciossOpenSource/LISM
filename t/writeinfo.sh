#!/bin/sh

if [ $# -lt 3 ]; then
    echo "bad parameters"
    exit 1
fi
INFO=$3
INFO=`echo $INFO | sed s/#[^#]*createtimestamp=[0-9]*Z//`
INFO=`echo $INFO | sed s/#[^#]*modifytimestamp=[0-9]*Z//`
OINFO=$4
OINFO=`echo $OINFO | sed s/#[^#]*createtimestamp=[0-9]*Z//`
OINFO=`echo $OINFO | sed s/#[^#]*modifytimestamp=[0-9]*Z//`
echo "rdn=$2#$INFO;$OINFO" | sed s/#/,/g > $1

exit 0
