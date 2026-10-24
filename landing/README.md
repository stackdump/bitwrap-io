# landing/

Static landing page for the apex domain https://bitwrap.io, linking the live Bitwrap music apps (beats.bitwrap.io, dj.bitwrap.io).

One self-contained file, `index.html`: no scripts, no external fonts or assets, no trackers. It is not embedded in or served by the bitwrap Go binary.

Deploy: copy `index.html` to `/var/www/bitwrap.io/index.html` on pflow.dev; nginx serves that directory statically for bitwrap.io. Only link apps that return 200 on their own domain.
