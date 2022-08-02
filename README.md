# simpledns

I wanted to make a really basic DNS server for my home network because I am too dumb to use the built-in linux dns servers.

# Ideas

- [x] yaml config file for custom records
  - [x] custom records for computers on my home server
  - [ ] pi-hole-like "dropping" of names
  - [ ] regex matching for name resolution
- [x] file watcher on the config file so we don't have to refresh the server for config changes
- [ ] recursive resolver
- [ ] in-memory and file-based caching for records that we have found

