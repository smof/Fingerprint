Fingerprint 0.1

A file finger printing and basic integrity monitoring application.

Synposis:
---------
Scans a master file list containing files to be monitored.  Creates a baseline report which contains an MD5 hash of the file, records the file size
and the last modification date of the file.  MD5 hashes are then taken of the master file list and baseline report and placed into an encrypted
init file to prevent tampering of the application results.

Periodic scan reports are then created, either manually or via cron, of the files contained in the master file list.  The hash of the master file
list if checked before the scan takes place to make no tampering has taken place.

After at least one periodic scan report has been completed, Fingerprint, can then be used with the -diff option which will compare the baseline to 
any scan reports that have been created.  Any hash differences are sent to a diff report which can be used for analysis.

Features
--------

INIT --> SCAN --> DIFF

./Fingerprint.rb --init				Performs initialisation.  Checks master file list, creates base line report, populates .init.rc 						file, deletes old reports.
./Fingerprint.rb --scan				Checks master file list, then performs a periodic scan.  Creates a scan CSV report file.
./Fingerprint.rb --diff				Performs a diff between the current baseline report and any selected periodic report.  Creates a 							diff CSV report file.
./Fingerprint.rb --help				Additional help

The default reports directory is reports/.

This should contain a master_file_list which will contain the paths of the files to be monitored.  One path per line.

After ./Fingerprint.rb --init is run, a file named .init.rc is created, which is a hidden, encrypted file, containing the baseline and master file list hash values.  This is used during --scan and -diff options to make sure no tampering has taken place on the actual reporting itself.

License
-------
Licensed under the GNU General Public License v3 - See LICENSE file for further details.

http://www.github.com/smof/fingerprint

