"""vendored_js_test: assert vendored copies match a pinned upstream."""

def _impl(ctx):
    script = ctx.actions.declare_file(ctx.label.name + ".sh")

    pairs = []
    for local, upstream in zip(ctx.files.vendored, ctx.files.upstream):
        pairs.append("%s\t%s" % (local.short_path, upstream.short_path))

    ctx.actions.write(
        output = script,
        is_executable = True,
        content = """#!/usr/bin/env bash
set -uo pipefail
fail=0
while IFS=$'\\t' read -r local upstream; do
    [ -z "$local" ] && continue
    if ! cmp -s "$local" "$upstream"; then
        echo "DIVERGED  $local"
        echo "          vendored copy differs from the pinned pflow-xyz upstream"
        diff -u "$upstream" "$local" | head -20
        fail=1
    fi
done <<'PAIRS'
{pairs}
PAIRS
if [ "$fail" -ne 0 ]; then
    cat >&2 <<'MSG'

These files are vendored from pflow-xyz and must match the commit pinned by
git_override in MODULE.bazel.

  - changed them upstream?  bump the pin, then: make sync-pflow-js
  - changed them here?      don't; make the change in pflow-xyz

MSG
    exit 1
fi
echo "vendored JS matches the pinned pflow-xyz upstream"
""".format(pairs = "\n".join(pairs)),
    )

    return [DefaultInfo(
        executable = script,
        runfiles = ctx.runfiles(files = ctx.files.vendored + ctx.files.upstream),
    )]

vendored_js_test = rule(
    implementation = _impl,
    test = True,
    attrs = {
        "vendored": attr.label_list(allow_files = True, mandatory = True),
        "upstream": attr.label_list(allow_files = True, mandatory = True),
    },
)
