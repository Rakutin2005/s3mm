# s3mmws modules

s3mmws can be extended with small shared objects, `s3mmws_mod_<name>.so`.
A module is loaded **only** when the s3mmws configuration names it:

```nginx
module s3mmc {
    config /etc/s3mm/s3mmc.conf;   # module specific directives
}
```

- File lookup: `path <file.so>;` inside the block, otherwise
  `<modules_dir>/s3mmws_mod_<name>.so`.
- The block is passed to `IRestModule::configure()`; a module that rejects
  its configuration stays disabled (logged at ERROR), s3mmws keeps running.
- Routes live under `/ext/<name>/`. Access needs `s3mmws:read` for `GET`
  and `s3mmws:write` otherwise (same RBAC as the rest of s3mmws).

## Web UI contribution

`IRestModule::uiExtension()` returns a declarative page description. s3mmws
serves all of them at `GET /ui/extensions`; the web UI adds one navigation
entry per extension (route `/ext/<id>`) and renders it generically, so a module
brings its page with it and the UI is not rebuilt. When the module is removed
from the configuration, the page disappears.

```json
{ "id": "s3mmc", "title": "Cluster mesh", "icon": "cluster", "refresh": 10,
  "sections": [
    { "type": "kv", "title": "Node", "source": "/ext/s3mmc/status",
      "fields": [ { "key": "node", "title": "Node" } ] },
    { "type": "table", "title": "Peers", "source": "/ext/s3mmc/peers", "path": "peers",
      "rowKey": "id",
      "columns": [ { "key": "id" }, { "key": "connected", "type": "bool" } ],
      "rowActions": [ { "label": "Remove", "method": "DELETE",
                        "endpoint": "/ext/s3mmc/peers?id={id}", "confirm": "Remove {id}?",
                        "danger": true } ] },
    { "type": "actions", "title": "Actions", "actions": [
      { "label": "Add peer", "method": "POST", "endpoint": "/ext/s3mmc/peers",
        "body": { "id": "{id}", "address": "{address}" },
        "fields": [ { "name": "id", "required": true }, { "name": "address", "required": true } ] } ] },
    { "type": "json", "title": "Raw status", "source": "/ext/s3mmc/status" }
  ] }
```

| Section | Shows |
|---|---|
| `kv` | object at `source` (+ `path`) as label/value pairs (`fields`, or all keys) |
| `table` | array at `source` (+ `path`) with `columns`; optional `rowActions` |
| `actions` | buttons; actions with `fields` open a form first |
| `json` | raw JSON |

Column/field `type`: `text` (default), `bool`, `tag`, `json`.
Icons: `cluster`, `api`, `cloud`, `database`, `link`, `monitor`, `setting`.
`{name}` placeholders in `endpoint` and `body` are filled from the form fields
or the table row. A `GET` action shows its JSON answer in a dialog.

## Writing a module

```cpp
#include "s3mm/rest/module.hpp"
#include "s3mm/rest/router.hpp"

class MyModule : public s3mm::rest::IRestModule {
public:
    s3mm::rest::RestModuleInfo info() const override { return {"my", "1.0", "me"}; }
    s3mm::Result<void> configure(const s3mm::config::Node& block) override;
    s3mm::Value uiExtension() const override;
    void registerRoutes(s3mm::rest::Router& r) override;
};
S3MM_REST_MODULE_ENTRY(MyModule)
```

Build it with `s3mmws_module(my modules/s3mmws/my/mod_my.cpp)` in
`CMakeLists.txt`. Modules log through the s3mmws logger (syslog).

## Bundled modules

| Module | Configuration | Page |
|---|---|---|
| `s3mmc` | `socket <s3mmc control socket>;` or `config <s3mmc.conf>;` (socket = `<run_dir>/<node>/s3mmc.sock`), `timeout 5s;` | node, peers (visibility, remove), links, cluster routes, add peer, sync inventory |
