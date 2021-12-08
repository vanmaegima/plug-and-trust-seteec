# edge-lock-device-link-rtp-server

Maven is used to compile and build jar files.

To compile and create jar file:
``mvn package``

Once compiled Remote Provisioning Server can be started with different command line options:

Print usage details.
`` mvn exec:java -Dexec.mainClass="com.nxp.iot.devicelink.RtpServer" -Dexec.arguments="-h"``

To get version of server:
`` mvn exec:java -Dexec.mainClass="com.nxp.iot.devicelink.RtpServer" -Dexec.arguments="-V"``

To start server on port 6789 and parse JSON files from "dir":
`` mvn exec:java -Dexec.mainClass="com.nxp.iot.devicelink.RtpServer" -Dexec.arguments="-d dir -p 6789"``
