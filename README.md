# simpledns

I wanted to make a really basic DNS server for my home network because I am too dumb to use the built-in linux dns servers.

# Ideas

- yaml config file for custom records
  - custom records for computers on my home server
  - ability to override name server resolution (like pi-hole)
  - regex matching for name resolution
- file watcher on the config file so we don't have to refresh the server for config changes
- recursive resolver
- in-memory and file-based caching for records that we have found

