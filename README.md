Code status:
------------

## TrustSQL: World 1st distributed ledger function enabled RDBMS

TrustSQL is designed as a node application in distributed ledger environment.
It replace peer application like as Bitcoin daemon or Ethreum daemon.
RDBMS is quite advanced data management method. Now you can use it on distributed ledger system with all features of RDBMS.

The base of TrustSQL is MariaDB v10.3.11.
It works same with MariaDB also because TrustSQL doens't remove any features of MariaDB.
TrustSQL just add some features for blockchain on MariaDB.

Now, all applcation developers on RDBMS can be blockchain or distributed ledger application developers with ease.
You just need very little efforts to understand how the TrustSQL makes trust on RDBMS
With detail, you have to learn how to design data schema to be trusted with additional constraints for trust.


Install:
--------
You can select build TrustSQL or MariaDB with compile options.

Use follow option.
-DCMAKE_TRUSTSQL_BUILD=Release

If you do not put the option, it works as a MariaDB server.

You can find my example in file cmake_trustsql


Who we are:
----------
TrustDB inc, is a distributed ledger technology company in South, Korea.
 

Help:
-----
If you need any help please send me an e-mail.
booltaking@hanmail.net


License:
--------

***************************************************************************

NOTE: 

TrustSQL is specifically available only under version 2 of the GNU
General Public License (GPLv2). (I.e. Without the "any later version"
clause.) This is inherited from MariaDB.

***************************************************************************


