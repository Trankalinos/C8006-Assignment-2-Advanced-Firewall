###############################################################################
##      David Tran, Cole Rees
##      Assignment 2 - COMP 8006
##      Thursday, February 20 2014
##
##      Stand-Alone Firewall README
###############################################################################

This file is to describe the replication of our assignment. 

To run the Firewalls script, please execute the following after giving proper
permissions:

    ./ext-firewall.sh

To run the supplementary test scripts, please execute the following after giving
proper permissions to the respective files:

    ./internal_scripts.sh (for the internal host)
    ./external_scripts.sh (for the external host)

Each of these scripts will create (and overwrite when ran again) a test results
file. These files are the following:

    int-test-results.txt (from internal_scripts.sh)
    ext-test-results.txt (from external_scripts.sh)

You should consult these test results alongside the main document, which includes
the test cases and the criteria as imposed by assignment 2.

Make sure that the internal host (which will act as the server) to have the proper
server capabilities. For the purpose of our assignment, we had apache and vsftpd
installed. We used a custom vsftpd.conf file, which is attached.

To make the physical connections between firewall and internal host, please 
consult the Design & Testing document located on-disk.
