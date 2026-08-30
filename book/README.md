# The straw manual

The source for the straw book — an [mdBook](https://rust-lang.github.io/mdBook/)
covering the CONNECT-IP proxy, the `strawc` client, and the `strawcat`
peer-to-peer direct path.

Chapters live in [`src/`](src/); [`src/SUMMARY.md`](src/SUMMARY.md) is the table
of contents (mdBook builds only what it lists). Configuration is in
[`book.toml`](book.toml).

## Building

Install mdBook (a single static binary), then build from this directory:

```bash
cargo install mdbook        # or: brew install mdbook
cd book
mdbook build                # renders HTML into book/ (gitignored)
```

Open `book/index.html` to read it.

## Live preview

`mdbook serve` rebuilds on save and serves at <http://localhost:3000>:

```bash
cd book
mdbook serve --open
```

## Adding a chapter

1. Create `src/ch-NN-MM-title.md` (the `ch-NN-MM` prefix mirrors the existing
   part/chapter numbering).
2. Add a link to it under the right heading in `src/SUMMARY.md` — a file not
   listed there is not built.
3. `mdbook build` (or keep `mdbook serve` running) to check it renders.

## Layout

The generated `book/` output directory is gitignored; only the source
(`book.toml` + `src/`) is tracked, so the book is always rebuilt from source.
