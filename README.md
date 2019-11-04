# Storyscript HTTP Gateway

API gateway server for executing Stories via HTTP.

```coffee
http server as server
  when server listen method:'get' path:'/' as r
    log info msg:r.body
    log info msg:r.headers
    log info msg:r.headers['Host']
    r write data:'Hello World'
    r status code:200
    r finish
```

```sh
$ curl https://foobar.storyscriptapp.com/
Hello World
```


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
