MODE="${1:-all}"
HPC="$2"
USERS=("astro1" "astro2" "astro3")
for user in "${USERS[@]}"; do
    sudo -u "$user" /mnt/nfs-share/test.sh $MODE $HPC &
done
wait
echo "Multi-user test completed."