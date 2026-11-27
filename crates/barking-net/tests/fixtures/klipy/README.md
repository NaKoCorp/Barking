# Klipy fixtures

These responses are **synthetic**. They were built on 2026-11-27 from the
response examples in Klipy's documentation (<https://docs.klipy.com>, pages
"GIF - Search API", "GIF - Trending API" and "GIF - Items API"), not captured
from the live API.

- `search.json`, `trending.json`: the documented example entry (`hello-hi-662`)
  plus a second made-up entry, reduced to the `mp4` renditions that
  `format_filter=mp4` asks for; `blur_preview` is shortened.
- `items.json`: the documented `gifs/items` example, every format kept.
- `items_empty.json`: `gifs/items` for an unknown slug. The documentation shows
  no such response; `{"result": true, "data": {"data": []}}` is a guess.

The documentation shows no author field, so `parse_item` returns no author.

## Refreshing

With your own key, outside the repository (the key must never be committed):

```sh
K=...  # your Klipy key
curl -s "https://api.klipy.com/api/v1/$K/gifs/search?q=hello&page=1&per_page=24&format_filter=mp4&content_filter=medium" > search.json
curl -s "https://api.klipy.com/api/v1/$K/gifs/trending?page=1&per_page=24&format_filter=mp4&content_filter=medium" > trending.json
curl -s "https://api.klipy.com/api/v1/$K/gifs/items?slugs=<a real slug>" > items.json
curl -s "https://api.klipy.com/api/v1/$K/gifs/items?slugs=no-such-slug-zz9" > items_empty.json
```

Check that the key appears in none of the files, then run
`BARKING_KLIPY_KEY=$K cargo test -p barking-net klipy_live_smoke -- --ignored --nocapture`,
which calls search and items for real and checks that they still parse.
