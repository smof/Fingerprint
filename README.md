Fingeprint 1.0

A file finger printing and basic integrity monitoring application.

Synposis:
---------
Scans a master file list containing files to be monitored.  Creates a baseline report which contains an MD5 hash of the file, records the file size
and the last modification date of the file.  MD5 hashes are then taken of the master file list and baseline report and placed into an encrypted
init file to prevent tampering of the application results.

Periodic scan reports are then created, either manually or via cron, of the files contained in the master file list.  The hash of the master file
list if checked before the scan takes place to make no tampering has taken place.

After at least one periodic scan report has been completed, Fingerprint, can then be used with the -diff option which will compare the baseline to any scan reports that have been created.  Any hash differences are sent to a diff report which can be used for analysis.

Features
--------
1	-	Simple file integrity checker
2	-	CSV report export
3	-	Tamper prevention
4	-	Scalable - reports created against 500k record master file list

License
-------
Licensed under the GNU General Public License v3 - See LICENSE file for further details.

http://www.github.com/smof/fingerprint

