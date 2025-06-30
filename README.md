# COMP3901-Mad-Hatters
A group project for COMP3901


The aim of this project is to allow users to be able to pick up on and avoid/prevent Evil Twin Attacks.

An Evil Twin Attack is a form of an attack where a hacker creates fake access points/ WiFi networks to mimic real ones in the aim of getting persons to join them to steal login and or data. 
These types of attacks are normally set-up in areas such as airports, hotels, cafes and other areas where there is an expectancy of large amounts of WiFi's available to the public for public usage. 

How an Evil Twin Attack Works 
Creation of Rogue Access Point: The attacker creates a wireless network with a name similar to or identical to a legitimate one. Users are likely to connect. If a WiFi network is called “CoffeeShopWiFi” in a public place, the attacker could create a rogue access point with the same name.

Signal Strength: An attacker will ensure that the rogue AP has a signal strength equal to or greater than the legitimate network. A stronger signal increases the likelihood of devices in the area automatically connecting to the rogue AP.

User Connection: Users in the vicinity could unknowingly connect to the evil network, thinking it is legitimate. Once connected, an attacker can intercept data sent between the user and the internet.

Man-in-the-Middle Attacks: By controlling the connection, the attacker can launch various attacks, including man-in-the-middle. These attacks allow them to intercept sensitive data such as usernames, passwords, or other data sent between the user and the internet.

Traffic Manipulation: The attacker may also manipulate traffic by redirecting users to malicious sites or injecting malicious content onto legitimate websites.

Social Engineering: Social engineering is used to trick users into connecting with the rogue access points. Users are often enticed by a familiar network name or the appearance of an open, free WiFi connection.


Terms to know:

SSID
BSSID
Channel
Beacon Interval
MAC 


There are different ways to try and detect an Evil Twin Attack but none are 90%-100% accurate and are best used together to lower the chance of false positives or false negatives.

Some methods are:
SSID Duplication	-  Testing for different networks with the same SSID, but can be very ineffective as mesh networks and within company buildings may reuse SSIDs. 
MAC Vendor Check	- Checks the MAC address to the vendor, if the AP name or if you can see the AP device itself you can see the brand/company, if it doesn't match the vendor the mac address is associated with it. There is a high possibilty that it has been tampered with and a high possiblity of being an Evil Twin.
Channel Comparison	
Signal Strength Analysis	- In some cases when a hacker might be using a mobile AP the signal strength can fluctuate heavily, but there is a possibilty that an legitimate AP has poor or fluctuating signal strength if there is a high interferance such as walls.
Beacon Frame Inspection	
SSL Certificate/Redirect Test	
DNS Analysis	
