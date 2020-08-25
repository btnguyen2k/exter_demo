A simple application to demonstrate [Exter](https://github.com/btnguyen2k/exter/).

## Live demo

See `exter_demo` in action at https://demo-exterapp.herokuapp.com/.

## Build and run on your machine

Build `exter_demo` with the following command:

```
$ go build -o main
```

And run it:

```
$ ./main
```

`exter_demo` now can be accessed at http://localhost:6789/.

**Configurations**

`exter_demo` can be configured via environment variables:

|Env|Default Value|Description|
|---|-------------|-----------|
|FORCE_LOGIN|`false`|If set, redirect user to Exter's `xlogin` page. Otherwise, redirect user to Exter's `xcheck` page.|
|EXTER_BASE_URL|`http://localhost`|Specify Exter's base URL (example `http://exteross.gpvcloud.com`)|
|HEROKU|`false`|Set if deploy on [Heroku](https://www.heroku.com/).|
