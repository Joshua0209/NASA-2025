#!/usr/bin/env bash

usage() {
#     cat <<EOF
# usage message
# EOF
    cat <<EOF
merkle-dir.sh - A tool for working with Merkle trees of directories.

Usage:
  merkle-dir.sh <subcommand> [options] [<argument>]
  merkle-dir.sh build <directory> --output <merkle-tree-file>
  merkle-dir.sh gen-proof <path-to-leaf-file> --tree <merkle-tree-file> --output <proof-file>
  merkle-dir.sh verify-proof <path-to-leaf-file> --proof <proof-file> --root <root-hash>

Subcommands:
  build          Construct a Merkle tree from a directory (requires --output).
  gen-proof      Generate a proof for a specific file in the Merkle tree (requires --tree and --output).
  verify-proof   Verify a proof against a Merkle root (requires --proof and --root).

Options:
  -h, --help     Show this help message and exit.
  --output FILE  Specify an output file (required for build and gen-proof).
  --tree FILE    Specify the Merkle tree file (required for gen-proof).
  --proof FILE   Specify the proof file (required for verify-proof).
  --root HASH    Specify the expected Merkle root hash (required for verify-proof).

Examples:
  merkle-dir.sh build dir1 --output dir1.mktree
  merkle-dir.sh gen-proof file1.txt --tree dir1.mktree --output file1.proof
  merkle-dir.sh verify-proof dir1/file1.txt --proof file1.proof --root abc123def456
EOF
}

fileHash () {
    [[ $# -ne 1 ]] && echo "Hash argument length != 1" && exit 10
    [[ ! -f "$1" ]] && echo "Hash file not exist: $1"  && exit 10
    echo `sha256sum $1 | awk '{print $1}' | xxd -r -p | xxd -p -c 0`
}

HexHash () {
    [[ $# -ne 1 ]] && echo "Hash argument length != 1" && exit 10
    # echo `echo -n $1 | xxd -r -p -c 0 | sha256sum | awk '{print $1}'`
    local hex=$1
    printf "%s" "$hex" | xxd -r -p | sha256sum | awk '{print $1}' | xxd -r -p | xxd -p -c 0
}


HexConcate () {
    [[ $# -ne 2 ]] && echo "Hex argument length != 2" && exit 10
    local a=$1
    local b=$2
    { printf "%s" "$a" | xxd -r -p; printf "%s" "$b" | xxd -r -p; } | xxd -p -c 0
}

get_k () {
    [[ $# -ne 1 ]] && echo "get_k argument length != 1" && exit 10
    local k=1
    local m=$1
    while [[ $(( k*2 )) -le $((m-1)) ]]; do 
        k=$(( k*2 ))
    done
    echo $k
}

lg () {
    [[ $# -ne 1 ]] && echo "lg argument length != 1" && exit 10
    [[ $1 -lt 1 ]] && echo "lg argument should >= 1" && exit 10
    local a=$(($1 - 1))
    local b=0
    while [[ a -ne 0 ]]; do 
        a=$(( a >> 1))
        ((b++))
    done
    echo "$b"
}

Valid () {
    echo "OK" && exit 0
}

Invalid () {
    echo "Verification Failed" && exit 1
}

LSB () {
    [[ $# -ne 1 ]] && echo "lg argument length != 1" && exit 10
    echo $(( $1 & 1 ))
}


build () {
    # parse build
    [[ $# -ne 3 ]] && usage && exit 1
    local found=0
    while [[ "$#" -gt 0 ]]; do
        case "$1" in 
            "--output")
                [[ "$#" -eq 1 ]] && usage && exit 1
                local merkle_tree_file=$2
                [[ ! (( ! -e "$merkle_tree_file" ) || ( -f "$merkle_tree_file" && (! -L "$merkle_tree_file") )) ]] && usage && exit 1
                shift 2
                ;;
            *)
                [[ found -ne 0 ]] && usage && exit 1
                found=1
                local dir=$1
                [[ (! -d "$dir") || -L "$dir" ]] && usage && exit 1
                shift
                ;;
        esac
    done

    exec > "${merkle_tree_file}"

    # find regular files
    mapfile -t files < <(find "$dir" -type f -printf '%P\n' | LC_COLLATE=C sort)
    printf "%s\n" "${files[@]}"
    echo

    # calculate file hashes
    local m=${#files[@]}
    for (( i=0; i<$m; i++)); do
        hash="$(fileHash $dir/${files[$i]})"
        hashes[i]=$hash
    done

    # calculate root hash
    IFS=":"
    echo "${hashes[*]}"
    while [[ $m -ne 1 ]]; do
        local newhashes=()
        local j=0
        for (( i=0; i<$((m-1)); i+=2 )); do
            hash1=${hashes[i]}
            hash2=${hashes[i+1]}
            newhashes[j]="$(HexConcate "${hash1}" "${hash2}")"
            newhashes[j]="$(HexHash "${newhashes[j]}")"
            ((j++))
        done
        echo "${newhashes[*]}"

        [[ $((m % 2)) -eq 1 ]] && newhashes+=(${hashes[$((m-1))]}) # last one

        hashes=("${newhashes[@]}")
        m="${#hashes[@]}"
    done
}

gen-proof () {
    # parse gen-proof
    [[ $# -ne 5 ]] && usage && exit 1

    local found=0
    while [[ "$#" -gt 0 ]]; do
        case "$1" in 
            "--output")
                [[ "$#" -eq 1 ]] && usage && exit 1
                local proof_file=$2
                [[ ! (( ! -e "$proof_file" ) || ( -f "$proof_file" && (! -L "$proof_file") )) ]] && usage && exit 1
                shift 2
                ;;
            "--tree")
                [[ "$#" -eq 1 ]] && usage && exit 1
                local tree_file=$2
                [[ (! -f "$tree_file") || -L "$tree_file" ]] && usage && exit 1
                shift 2
                ;;
            *)
                [[ found -ne 0 ]] && usage && exit 1
                found=1
                local path_to_leaf_file=$1
                shift
                ;;
        esac
    done

    # get leaf_index and tree_size
    local leaf_index="$( grep -n "^$path_to_leaf_file$" $tree_file | cut -d: -f1 )"
    [[ -z $leaf_index ]] && echo "ERROR: file not found in tree" && exit 1
    local tree_size=$(("$( grep -n "^$" $tree_file | cut -d: -f1 )"-1))

    exec > "${proof_file}"
    echo "leaf_index:${leaf_index},tree_size:${tree_size}"

    # get proofs
    local s=1
    local t=$tree_size
    local j=$leaf_index
    local m=$(( $t - $s + 1))
    local ps=1
    local pt=1
    local proof=()
    local base=$(($tree_size + 2))
    IFS=":"
    while [[ m -ne 1 ]]; do
        local k="$( get_k $m )"
        [[ j -le k ]] && ps=$(( $s + $k )) && pt=$(( $s + $m - 1 )) && t=$(( $s + $k - 1))
        [[ j -gt k ]] && ps=$s && pt=$(( $s + $k - 1 )) && j=$(( $j - $k )) && t=$(($s + $m - 1)) && s=$(( $s + $k ))
        local m=$(( $t - $s + 1))
        echo "pi($j, $s:$t) k=$k m=$m proof=$ps:$pt">&2

        local sep=$(( $pt - $ps + 1 ))
        local dep="$( lg $sep )"
        local line_no=$(($base + $dep))
        line="$(sed -n "${line_no}"'p' "${tree_file}")"
        read -a hashes <<< "$line"

        sep=$((1 << $dep))
        [[ $sep -ne 1 ]] && local idx=$(( $ps / $sep))
        [[ $sep -eq 1 ]] && local idx=$(( $ps - 1 ))

        proof=("${hashes[$idx]}" "${proof[@]}")

        echo "sep=$sep, dep=$dep, idx=$idx, line=$line_no">&2
    done
    printf "%s\n" "${proof[@]}"

}

verify-proof() {
    # parse verify-proof
    [[ $# -ne 5 ]] && usage && exit 1

    local found=0
    while [[ "$#" -gt 0 ]]; do
        case "$1" in 
            "--proof")
                [[ "$#" -eq 1 ]] && usage && exit 1
                local proof_file=$2
                [[ (! -f "$proof_file") || -L "$proof_file" ]] && usage && exit 1
                shift 2
                ;;
            "--root")
                [[ "$#" -eq 1 ]] && usage && exit 1
                local rootHash=$2
                [[ ! ("$rootHash" =~ ^[0-9A-F]+$ || "$rootHash" =~ ^[0-9a-f]+$) ]] && usage && exit 1 
                shift 2
                ;;
            *)
                [[ found -ne 0 ]] && usage && exit 1
                found=1
                local f=$1
                [[ (! -f "$f") || -L "$f" ]] && usage && exit 1
                shift
                ;;
        esac
    done

    mapfile -t lines < "$proof_file"
    local k=$(echo "${lines[0]}" | awk -F'[:,]' '{print $2}')
    local n=$(echo "${lines[0]}" | awk -F'[:,]' '{print $4}')
    local h="$( fileHash $f )"
    echo "k:$k, n:$n">&2
    echo "$h">&2
    k=$(( k - 1 ))
    n=$(( n - 1 ))
    for (( i=1; i<${#lines[@]}; i++)); do 
        [[ n -eq 0 ]] && Invalid
        local lsb_k="$( LSB $k )"
        if [[ lsb_k -eq 1 || k -eq n ]]; then
            h="$( HexConcate ${lines[$i]} $h )"
            h="$( HexHash $h )"
            while [[ lsb_k -eq 0 ]]; do
                k=$((k >> 1))
                n=$((n >> 1))
                lsb_k="$( LSB $k )"
            done
        else
            h="$( HexConcate $h ${lines[$i]} )"
            h="$( HexHash $h )"
        fi
        k=$((k >> 1))
        n=$((n >> 1))
        lsb_k="$( LSB $k )"
        echo "$h">&2
    done
    echo "$n">&2
    echo "$rootHash">&2
    [[ n -eq 0 && ${h,,} = ${rootHash,,} ]] && Valid
    Invalid
}

case "$1" in
    -h|--help)
        usage
        [[ $# -eq 1 ]] && exit 0
        exit 1
        ;;
    build)
        shift 
        build "$@"
        exit 0
        ;;
    gen-proof)
        shift
        gen-proof "$@"
        exit 0
        ;;
    verify-proof)
        shift
        verify-proof "$@"
        exit 0
        ;;
    *)
        usage
        exit 1
        ;;
esac