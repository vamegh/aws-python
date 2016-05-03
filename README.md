# aws-python

This is using: http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html

I am trying to avoid using boto2 and to query the api directly via requests to gather information about aws instances.

test.py currently gathers vpc information from eu-west-1 and is a modification of their test example -- the only real difference
is gathering vpc data and an attempt to sanitise the xml output and convert it to json / python native data format to make gathering and displaying information a lot easier.

This is still in heavy work in progress -- should have something sane running soon.

