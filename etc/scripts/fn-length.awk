# Report Zig functions longer than `max` lines (signature through closing brace).
# Relies on zig fmt: a function body ends at the first `}` line at the `fn` indentation.
# Output: file:line: fn name is N lines (max M)
FNR == 1 { open = 0 }
{
  if (open && $0 == indent "}") {
    len = FNR - start + 1
    if (len > max) printf "%s:%d: fn %s is %d lines (max %d)\n", FILENAME, start, name, len, max
    open = 0
  }
  if (!open && match($0, /^[ ]*(pub )?(export )?(inline )?(noinline )?fn [A-Za-z0-9_@"]+\(/)) {
    line = $0
    if (line ~ /;[ ]*$/) next          # extern / prototype
    if (line ~ /\) type \{[ ]*$/) next  # generic type constructor: a struct definition
    match(line, /^[ ]*/); indent = substr(line, 1, RLENGTH)
    sub(/^.*fn /, "", line); sub(/\(.*/, "", line); name = line
    start = FNR; open = 1
    if ($0 ~ /\}[ ]*$/ && $0 ~ /\{/) open = 0   # one-liner
  }
}
