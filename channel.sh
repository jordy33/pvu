#!/bin/bash

# dependency - jq
# debian/ubuntu - apt-get install jq
# redhat/centos - yum install jq

############### BEGIN CONFIG ###################
streamer="192.168.1.91:9981"
tmpfile="/tmp/services.json"
profile="PowerVu"
streamauth="pvu:pvu"
apiauth="admin:trinity"
###############  END CONFIG  ###################

wget -O /tmp/services.json http://${apiauth}@localhost:9981/api/mpegts/service/grid?limit=100000
echo \#EXTM3U
entries=$(/usr/bin/jq -c  '.total' ${tmpfile})
for (( service=0; service<= $entries; service++ ))
do
        if [ $(/usr/bin/jq -c '.entries['$service'].caid' ${tmpfile}) = '"0E00:000000"' ]
        then
                enabled=$(/usr/bin/jq -c  '.entries['$service'].enabled' ${tmpfile})
                if [ "$enabled" = "true" ]
                then
                        svcname=$(/usr/bin/jq -c -r  '.entries['$service'].svcname'  ${tmpfile})
                        uuid=$(/usr/bin/jq -c -r  '.entries['$service'].uuid'  ${tmpfile})
                        network=$(/usr/bin/jq -c -r  '.entries['$service'].network'  ${tmpfile})
                        multiplex=$(/usr/bin/jq -c -r  '.entries['$service'].multiplex'  ${tmpfile})
                        sid_dec=$(/usr/bin/jq -c  '.entries['$service'].sid'  ${tmpfile})
                        sid=$(printf '%x' $sid_dec)
                        echo \#EXTINF:-1, $network/$multiplex/$svcname
                        echo http://${streamauth}@${streamer}/stream/service/${uuid}\?profile=${profile}\&descramble=1\&emm=1\&:0:0:${sid}
                fi
        fi
done

