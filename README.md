# ErgoPool Api
This project is a api server for [ergopool.io](https://ergopool.io) now ergopool is closed due to incoming hardfork of Ergo. 
Ergopool is an impotent semi-decentralized mining pool built to empower the most decentralized blockchain ever existed.
## Setup
### Prerequisite
  * python:3.7
  * django>=2.2,<2.3
### Getting Started

The best solution for starting this service is, build [Dockerfile](https://github.com/ergopool-io/ergoapi/blob/master/Dockerfile) and use it.

First clone the repository from Github and switch to the new directory:
```
$ git clone https://github.com/ergopool-io/ergoapi.git
$ cd ergopai
```

Install project dependencies:
```
$ pip3 install -r requirements.txt
```

For config app in development mode use [production.py.sample](https://github.com/ergopool-io/ergoapi/blob/master/ErgoApi/production.py.sample) and rename this file to `production.py` and for production mode use this file [production.py](https://github.com/ergopool-io/ergoapi/blob/master/config/production.py) and after config default value or set enviroment for parameters move this file to [this path](https://github.com/ergopool-io/ergoapi/blob/master/ErgoApi/).

Then simply apply the migrations:
```
$ python manage.py migrate
```

Note: for running ergoapi service you need to run [ergotxverify](https://github.com/ergopool-io/ergotxverify) and [ergoaccounting](https://github.com/ergopool-io/ergoaccounting), also you need to set up an [Ergo node](https://github.com/ergoplatform/ergo.git) and set url them to the config file `production.py`.

You can now run the development server :
```
$ python manage.py runserver
```

In this project there is no migration and communicate with database, ergoapi service receives a block header, share, txp, and proof of txp. it will check the block header and verifies the txp and its proof. if all conditions passed (non-redundant share, block format, txp included, valid share,...) the [accounting](https://github.com/ergopool-io/ergoaccounting) system will add one share to the user's share. Another function of this service was to send other requests to the accounting service, in a way, it acts as a proxy between the requests of miners and the APIs of the accounting service.
