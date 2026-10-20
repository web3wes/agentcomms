#!/bin/sh
set -eu

for fuzzer in "$SRC"/agentcomms/fuzz/*_fuzzer.py; do
  name=$(basename "$fuzzer" .py)
  package="$name.pkg"
  pyinstaller --distpath "$OUT" --onefile --name "$package" "$fuzzer"
  cat > "$OUT/$name" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput marker for ClusterFuzzLite discovery.
this_dir=\$(dirname "\$0")
exec "\$this_dir/$package" "\$@"
EOF
  chmod +x "$OUT/$name"
done
