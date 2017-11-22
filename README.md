# Log Parser

Log Parser H is a flask powered web app that displays log entries.
### User Guide
* To view all the available options, navigate to /
* To view all traffic list with the unique ips, countries and hits, navigate to /traffic
* To view all sql injections attacks with their entries, navigate to /sqli_exploit
* To view all LFI attack attempts with their entries, navigate to /lfi_exploit
* To view all RFI attack attempts with their entries, navigate to /rfi_exploit

### Installation

Log Parser H requires [Pipenv](https://http://pipenv.org//) to run.

Install the dependencies and run the build script. The script will take care of db creation and parsing before running the app.

```sh
$ cd log_parser_h
$ pipenv install
$ sh build.sh
$ python runserver.py
```

### Installation via Docker
Log Parser H can also be installed via Docker
by default, the Docker will expose port 80, change this within the Dockerfile if necessary.

note: the build takes a while due to the parsing of the logs
```sh
$ cd log_parser_h
$ docker build -t logparser .
```

Once done, run the Docker image and map the port to wherever you wish.

```sh
docker run -d -p 5000:80 logparser
```

Verify the deployment by navigating to your server address in your preferred browser.

```sh
127.0.0.1:5000
```

### Development

It's recommended to use [konch](http://github.com/sloria/konch) with ipython in cases where you need app context to debug


### Todos

 - Write a ReactJS frontend
 - Upload a proper docker container for it

License
----

MIT
