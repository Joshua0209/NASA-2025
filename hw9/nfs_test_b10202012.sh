#!/bin/bash
# NASA HW9 Part 3 Script
# Usage: ./nfs_test_ID.sh [write|read|all]
# [cite_start]Source Requirement: 1GB file size [cite: 126][cite_start], Record MB/s & CPU load [cite: 133]

# 取得第一個參數，若無則預設為 "all"
MODE="${1:-all}"
HPC="$2"

# 定義檔案名稱 (移除 RANDOM 以便分開測試時能找到同一份檔案)
FILENAME="testfile_$(whoami)_$HPC"
TARGET="/mnt/nfs-share/$(whoami)_dir/$FILENAME"
SIZE="1G" 

echo "=== NFS Performance Test for User: $(whoami) ==="
echo "Mode: $MODE"
echo "Target: $TARGET"

# --- 函式：寫入測試 ---
do_write() {
    echo "------------------------------------------------"
    echo "[Write Test] Starting... (Size: $SIZE)"
    
    # 抓取開始前的 Loading
    START_CPU=$(cat /proc/loadavg | awk '{print $1}')
    
    # 執行寫入 (oflag=direct 避開 Client Cache)
    # count=1024 * bs=1M = 1GB
    WRITE_RES=$(dd if=/dev/zero of="$TARGET" bs=1M count=1024 oflag=direct status=progress 2>&1)
    
    # 抓取結束後的 Loading
    END_CPU=$(cat /proc/loadavg | awk '{print $1}')
    
    # 解析並顯示結果
    WRITE_SPEED=$(echo "$WRITE_RES" | tail -n 1)
    echo ">> Write Result: $WRITE_SPEED"
    echo ">> System Load (Start -> End): $START_CPU -> $END_CPU"
}

# --- 函式：讀取測試 ---
do_read() {
    echo "------------------------------------------------"
    echo "[Read Test] Starting..."

    # 檢查檔案是否存在
    if [ ! -f "$TARGET" ]; then
        echo "Error: Target file $TARGET does not exist!"
        echo "Please run 'write' test first."
        return
    fi

    START_CPU=$(cat /proc/loadavg | awk '{print $1}')
    
    # 執行讀取 (讀到 /dev/null)
    READ_RES=$(dd if="$TARGET" of=/dev/null bs=1M status=progress 2>&1)
    
    END_CPU=$(cat /proc/loadavg | awk '{print $1}')
    
    # 解析並顯示結果
    READ_SPEED=$(echo "$READ_RES" | tail -n 1)
    echo ">> Read Result: $READ_SPEED"
    echo ">> System Load (Start -> End): $START_CPU -> $END_CPU"
}

# --- 主程式邏輯 ---

if [ "$MODE" == "write" ]; then
    do_write

elif [ "$MODE" == "read" ]; then
    do_read

elif [ "$MODE" == "all" ]; then
    do_write
    do_read
    # 只有在跑完全部流程時，才自動刪除檔案
    echo "------------------------------------------------"
    echo "Cleaning up $TARGET..."
    rm -f "$TARGET"
else
    echo "Usage: $0 [write|read|all]"
    exit 1
fi

echo "=== Test Finished ==="