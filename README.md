# heartbeat

To see whether your server is vulnerable to the TLS Heartbleed attack, simply run

```bash
$ ruby heartbeat.rb <server> [<port>]
```

If no port is specified, 443 is assumed as the default.
 
If you'd like to check a list of sites, you can specify a CSV file instead of a server. (N.B. URL is expected, i.e. google.com, in 2nd field, per [Alexa's CSV](http://s3.amazonaws.com/alexa-static/top-1m.csv.zip)).

```bash
$ ruby heartbeat.rb <file> [<port>]
```

### Disclaimer

Do not use this script to cause harm.

### License

None.

### Further info

See http://heartbleed.com/ for further infos on the attack.
