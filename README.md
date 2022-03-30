# Spotify Connect

Use `spotify-connect` to authenticate yourself on remote devices. Theses devices will then be controllable by the [Spotify Web API](https://developer.spotify.com/documentation/web-api/) (through [`rspotify`](https://github.com/ramsayleung/rspotify) or [`spotify-tui`](https://github.com/Rigellute/spotify-tui) for example).

> I don't have any official device with Spotify Connect. I made this tool to register my [`librespot`](https://github.com/librespot-org/librespot) receivers. So, it has not been tested on official hardware. It may work. But it will certainly fail.


## Installation

There is no package yet. There is even no crate yet. Early-stage at its highest!

Fortunately, we can rely on `git` and `cargo` for the installation:

```shell
git clone https://github.com/TimotheeGerber/spotify-connect.git
cd spotify-connect
cargo install --path .
```


## Usage

```shell
spotify-connect <IP> <PORT> [PATH]
```

Automatic discovery of devices is not implemented yet. You have to find the `IP` address of your receiver, the `PORT` Spotify Connect is listening to and, optionally, the `PATH` to the ZeroConf API on the device web server. The `PATH` should always start with a `/` character.

The following `avahi` command should provide everything needed:

```shell
avahi-browse --resolve _spotify-connect._tcp
```

If it is the first time you use `spotify-connect`, your Spotify credentials will be asked (username/password). Reusable credentials will be automatically cached for future `spotify-connect` calls. On Linux, the credentials should be cached in `$HOME/.cache/spotify-connect/credentials.json`.

> Reusable credentials are provided by Spotify and are encrypted. Your password is not stored as plain text. However, you can set the permissions of the cache directory to `700` to improve security.

If the default authentication method is not working on your devices, you can try alternative methods with the `--auth-type <AUTH_TYPE>` option.

```shell
spotify-connect --auth-type access-token <IP> <PORT> [PATH]
```

Type `spotify-connect --help` to see the list of all authentication methods currently implemented.


## Roadmap

The following steps are planned:

 - test it on officially supported devices (help needed);
 - add a feature to enable automatic device discovery;
 - upload this on crates.io as a lib and executable.


## Disclaimer

I did not read all Spotify legal notices, but I am pretty sure that using this tool is forbidden by them. Use at your own risk! And if you work at Spotify, please, don't hurt me!


## Thanks

Many thanks to the people behind [`librespot`](https://github.com/librespot-org/librespot)! Chunks of code are largely inspired by their excellent work.
