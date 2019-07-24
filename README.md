# Asyncy HTTP Gateway

API gateway server for executing Stories via HTTP.

```coffee
http server as server
  when server listen method:"get" path:"/user/:name/*" as r
    log info msg:r.body
    log info msg:r.headers
    log info msg:r.headers["Host"]
    log info msg:r.path_params
    log info msg:r.path_params["name"]
    log info msg:r.path_params["wildcard"]
    
    r write data:"Hello {r.path_params["name"]}"
    r status code:200
    r finish
```

```sh
$ curl https://foobar.storyscriptapp.com/
Hello World
```

## Routing
```coffee
  path:'/pages/new'               # Matches ONLY /pages/new
  path:'/pages/:id'               # Matches /pages/25
  path:'/pages/:id/*'             # Matches /pages/10/any/thing/else
  path:'/page*'                   # Matches /pages/10 or /page_any_thing/else
  path:'/pages/:id/*/:source/end' # Matches /pages/9/any/thing/some_source/end
  path:'/*'                       # Matches everything
````

## Development

Setup virtual environment and install dependencies
```
virtualenv -p python3.6 venv
source venv/bin/activate
pip install -r requirements.txt
```

You may need to tell pycurl the path to your openssl installation
```
pip install --install-option="--with-openssl" --install-option="--openssl-dir=/usr/local/opt/openssl" pycurl
```
See https://github.com/nahamsec/JSParser/issues/22


Run locally by calling

```
python -m app.main --logging=debug --debug
```

### Register an endpoint

```shell
curl --data '{"endpoint": "http://localhost:9000/story/foo", "data":{"path":"/ping", "method": "post", "host": "a"}}' \
     -H "Content-Type: application/json" \
     localhost:8889/register
```

Now access that endpoint

```shell
curl -X POST -d 'foobar' -H "Host: a.storyscriptapp.com" http://localhost:8888/ping
```


### Unregister an endpoint

```shell
curl --data '{"endpoint": "http://localhost:9000/story/foo", "data":{"path":"/ping", "method": "post", "host": "a"}}' \
     -H "Content-Type: application/json" \
     localhost:8889/unregister
```
