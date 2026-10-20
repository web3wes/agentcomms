#!/bin/sh
set -eu

for fuzzer in "$SRC"/agentcomms/fuzz/*_fuzzer.py; do
  name=$(basename "$fuzzer" .py)
  package="$name.pkg"
  pyinstaller --distpath "$OUT" --onefile --name "$package" \
    --paths "$SRC/agentcomms" \
    --hidden-import agentcomms \
    --hidden-import agentcomms_v2 \
    "$fuzzer"
  cat > "$OUT/$name" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput marker for ClusterFuzzLite discovery.
this_dir=\$(dirname "\$0")
exec "\$this_dir/$package" "\$@"
EOF
  chmod +x "$OUT/$name"
done
