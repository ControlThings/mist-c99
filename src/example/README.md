# Mist example app

This is an example of a minimal Mist app. The example targets a Linux
system, and uses the libuv core client.

The libmist.a must first be compiled, see the static lib makefile in
mist-c99.

Then, "make" should do the job. You need to have libuv1 installed, so
that we can link against it.

## Service name from env

You can set the service name which is used when registering to the Wish
core. Set the environment variable 

```sh
TEST_INSTANCE_NAME="foobar" ./example-mist-app
```
