```
usage: tcping.py [-h] [-se SENDER_EMAIL] [-ps SENDER_PASSWORD] [-re RECV_EMAIL] [-ei EMAIL_INTERVAL] [-n PACKAGES_NUMBER] [-t TIMEOUT] [-i INTERVAL]
                 targets [targets ...]

positional arguments:
  targets              target is str like <ip>:<port> NO SPACES IN TARGET, SPACES ONLY BETWEEN TARGETS example: 1.1.1.1-50,59:80-90,5000

optional arguments:
  -h, --help           show this help message and exit
  -se SENDER_EMAIL     sender email
  -ps SENDER_PASSWORD  sender email password
  -re RECV_EMAIL       receiver email
  -ei EMAIL_INTERVAL   email report interval in seconds
  -n PACKAGES_NUMBER   default=+inf
  -t TIMEOUT           in seconds (float), default=+inf
  -i INTERVAL          in seconds (float)
```

OS
---
1. Only Linux

BEFORE START
---
1. Enter the net intervace into `NET_INTERFACE_NAME` in `environment.py`

Email sending
---
1. Using smtp.gmail.com => sending reports only via gmail => you need to get app-password in google account settings
