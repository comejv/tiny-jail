#!/bin/bash

set -e

STATS_FILE="tiny-jail/data/coreutils_stats.json"
BINARY="./target/release/tiny-jail"

# Common coreutils to test
COREUTILS=(
  "ls -la /tmp"
  "cat /etc/hostname"
  "echo hello"
  "wc -l /etc/passwd"
  "head -5 /etc/passwd"
  "tail -5 /etc/passwd"
  "cut -d: -f1 /etc/passwd"
  "sort /etc/hostname"
  "uniq /etc/hostname"
  "tr 'a-z' 'A-Z' < /etc/hostname"
  "grep root /etc/passwd"
  "sed 's/root/admin/' /etc/passwd"
  "find /tmp -type f -print"
  "basename /etc/hostname"
  "dirname /etc/hostname"
  "stat /etc/hostname"
  "file /bin/ls"
  "test -f /etc/hostname"
  "pwd"
  "whoami"
  "id"
  "date"
  "uname -a"
  "uptime"
  "df -h"
  "du -sh /tmp"
)

function run_cmd() {
  local -n cmds=$1
  for cmd in "${cmds[@]}"; do
    timeout 10s $BINARY --batch -e exec --watch-all-logs --stats-output "$STATS_FILE" -- bash -c "$cmd" 2>/tmp/stats.log &&
      echo "Ok: $cmd" || echo "Nok: $cmd"
  done
}

echo "Running coreutils through tiny-jail..."
run_cmd COREUTILS

STATS_FILE="tiny-jail/data/gcc_stats.json"

cat >/tmp/test_print.c <<'EOF'
#include <stdio.h>
int main() { printf("Hello, world!\n"); return 0; }
EOF

cat >/tmp/test_loop.c <<'EOF'
#include <stdio.h>
int main() {
  int i;
  for (i = 0; i < 10; i++) {
    printf("Hello, world!\n");
  }
  return 0;
}
EOF

GCC_CMDS=(
  "gcc -o /tmp/a.out /tmp/test_print.c"
  "gcc -Ofast -o /tmp/a.out /tmp/test_loop.c"
)

echo "Running gcc through tiny-jail..."
run_cmd GCC_CMDS

echo "Stats accumulated in $STATS_FILE"
