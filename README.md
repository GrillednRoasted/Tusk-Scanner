# Tusk-Scanner

Tusk scanner is a small intrusion prevention system, it scans the network for any malicious ips and unusual traffic.
By capturing the ips from active traffic in the network and sending them to a malicous ip database, the tusk scanner will return 
a confidence score for the likelihood on it being malicous and will automatically block any traffic to that ip. The user has the 
option to disable this feature and unblock any ips they wish.

To make Tusk scanner function properly, make sure to set the network interface to your own, and have snort installed and configured.
You can configure snort at "/etc/snort/snort.conf". 
Have an api-key.txt file ready in the directory with your personal api key for abuseipdb.com!
The password required for email notifications is your gmail app password, make sure to keep that on hand!

I will be working on updating the scanner more in the future so be on the lookout for that!!
