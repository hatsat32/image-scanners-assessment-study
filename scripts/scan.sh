#!/bin/bash

mkdir -p trivy grype snyk

while read image; do
    echo "[+] Started scanning image: '$image'"

    # ------------------------------------
    imagefile="$(echo $image | sed -e 's/\//__/' | sed -e 's/:/__/')"
    # ------------------------------------

    echo "[+] Pulling image: $image"
    docker pull -q $image

    if [ $? -ne 0 ]; then
        echo "[!] error pulling image: $image"
        continue
    fi

    echo "[+] Started trivy scan: $image"
    trivy image $image -q --format json -o trivy/$imagefile.json

    echo "[+] Started grype scan: $image"
    grype $image -q --output json > grype/$imagefile.json

    echo "[+] Started snyk scan: $image"
    timeout 10m snyk container test $image --json > snyk/$imagefile.json

    echo "[+] Deleting image: $image"
    docker image rm $image

    # echo "[+] Sleeping for 2m"
    # sleep 1m
done < remaining.images.txt
# done < library.all.txt


# file:
# alpine
# debian
# ubuntu

