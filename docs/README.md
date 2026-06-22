# go53 documentation

Source documentation in Markdown. Each page carries YAML front matter (`title`,
`weight`, `description`) and `_index.md` files are section landing pages — so the
navigation/sidebar build automatically.

This folder **is a self-contained [Hugo](https://gohugo.io) site**: a theme-less
layout in `layouts/` renders the docs with go53 branding (logo, favicons, teal
color scheme) and a sidebar generated from the content tree. The Markdown stays
at the folder root so it also browses cleanly on GitHub; `hugo.toml` module
mounts expose it to Hugo as `content/`, and `images/` + `api/` as static assets.

```
hugo.toml              Hugo config (branding params, module mounts)
layouts/               theme-less templates (baseof, head, sidebar, index landing)
_index.md              Home front matter (the landing page is layouts/index.html)
INSTALLATION.md        Install / quickstart            (top-level page)
CONTAINER.md           Container deployment            (top-level page)
RELEASES.md            Release notes                   (top-level page)
guides/                Task walkthroughs (server, primary/secondary, dnssec, ...)
concepts/              Explanatory deep-dives (DNSSEC, distributed mode)
reference/             Configuration, API, releases
internal/              Engine internals (storage / zone / RFC compliance)
api/openapi.yaml       REST spec for the admin API (served at /api/)
images/                Brand images + favicons (served at the site root)
```

## Build / preview

```sh
cd docs
hugo server          # live preview at http://localhost:1313
hugo --minify        # build static site into ./public
```

The public landing page (mapped to go53.eu) is the bespoke `layouts/index.html`;
it links into the documentation sections. Documentation pages use the sidebar
layout in `layouts/_default/`. Branding/colors live in
`layouts/partials/head.html`; the landing page carries its own inline styles.
