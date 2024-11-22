# CoderDojo

A fictional booking system for the Raspberry Pi Foundation.

## Getting Started

These instructions will give you a copy of the project up and running on
your local machine for development and testing purposes.

### Prerequisites

Requirements for the software 
- [Python](https://www.python.org/downloads/)
- (Optional) Mail Server

### config.py

> [!IMPORTANT]
> This file is required, without it the website will not function.<br>
> This file should be in the root directory of the project.<br>
> If you do not have a mail server, keep all fields default.

```python
import uuid

class Config:
    SECRET_KEY = uuid.uuid4().hex

    MAIL_SERVER = ''
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = ''
    MAIL_PASSWORD = ''
    MAIL_DEFAULT_SENDER = ''

```

### Installing

Installing required libraries

```
pip install -r requirements.txt
```

Running the main website

```
python main.py
```

Running PocketBase for testing purposes **(Optional)**

```
.\pb serve
```

### Running

Open the main website

```
localhost:5000
```

(Optional) Open PocketBase

```
localhost:8090/_/
```

> [!TIP]
> PocketBase Email: test@test.com<br>
> PocketBase Password: admin12345!
