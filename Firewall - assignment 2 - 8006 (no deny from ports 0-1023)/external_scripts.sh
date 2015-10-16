################################################################################
#------------------------------------------------------------------------------#
#
#	Filename: 	external_scripts.sh
#
#	Authors:	David Tran - A00801942
#			Cole Rees  - A00741578
#
#	Date:		Thursday, February 20 2014
#
#	Usage:		./external_scripts.sh
#
#------------------------------------------------------------------------------	
#	
#	Description: 	Used as a supplementary testing peripheral in 
#			conjunction with ext-firewall.sh (located on-disk)
#			after the aforementioned script has been executed.
#			User-defined variables are available for the user to
#			change for testing purposes.
#
#		        Test Cases are clearly outlined. When the script is
#		        finished running, a test-results.txt file will contain
#		        the results of test cases defined here.
#
#			This script shall be ran on an external host of our
#			architecture.
#	
#			Warning: This test script will take a few moments to
#			complete. To reduce the time for testing, reduce the
#			COUNT variable to less than 5. This, however, will
#			sacrifice testing effectiveness.
#
#		        Note: Editing the test cases is up to the discretion
#		        of the user. You have been warned.
#
#------------------------------------------------------------------------------#
################################################################################

#------------------------------------------------------------------------------#
#--------------------------- USER DEFINED VARIABLES ---------------------------#
#------------------------------------------------------------------------------#
FW_HOST="192.168.0.14"
FW_SCRIPT="ext-firewall.sh"
INT_NW="192.168.10.0/24"
INT_IF="192.168.10.1"
INT_HOST="192.168.10.2"

ALLOWED_TCP=('80' '443' '22' '21' '25')			# array, to loop through
ALLOWED_UDP=('53' '67' '68')				# array, to loop through

DISALLOWED_TCP=('8080' '4434' '222' '212' '252')	# array, to loop through
DISALLOWED_UDP=('534' '678' '689')			# array, to loop through

COUNT="5"
file="./ext-test-results.txt"

#------------------------------------------------------------------------------#
#------------------------------ Preliminary Setup -----------------------------#
#------------------------------------------------------------------------------#
if test -s "$file"
then
    echo "File exists. Deleting old results..."
    rm $file    
    touch $file
    # create fancy header here.
    echo "Hello World! Deleted old, created new." > $file
else
    echo "Creating new test results file..."
    touch $file
    # create fancy header here.
    echo "Hello World! Created new." > $file
fi

#------------------------------------------------------------------------------#
#-------------------------------- Test Case # 1 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #1 - Firewall Host ($FW_HOST) has limited external access" >> $file
echo "Note: To be tested using different methods." >> $file
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case # 2 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #2 - Internal Host ($INT_HOST) has external access" >> $file
echo "Note: To be tested using different methods." >> $file
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case # 8 -------------------------------#
#------------------------------------------------------------------------------#
# Test Case 8: ICMP drops
echo -en "\n\n" >> $file
echo "Test Case: #8 - ICMP (expected drops)" >> $file
hping3 $FW_HOST -p icmp --icmp-ipid 30 -c $COUNT >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case # 9 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #9 - Default Policies to be dropped" >> $file
hping3 $FW_HOST -S -c $COUNT -p 1337 >> $file 2>&1
hping3 $FW_HOST --udp -c $COUNT -p 1337 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #10 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #10 - External communication w. Firewall dropped" >> $file
hping3 $FW_HOST -S -c $COUNT -a 192.142.232.7>> $file 2>&1
hping3 $FW_HOST --udp -c $COUNT -a 192.142.232.7>> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #11 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #11 - Drop all packets pretending to be internal host" >> $file
hping3 $FW_HOST -S -c $COUNT -a $INT_HOST>> $file 2>&1
hping3 $FW_HOST --udp -c $COUNT -a $INT_HOST>> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #13 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #13 - Reject inbound SYN packets (no target port)" >> $file
hping3 $FW_HOST -S -c $COUNT >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #14 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #14 - Reject inbound SYN packets ('high port' target)" >> $file
hping3 $FW_HOST -S -c $COUNT -p 36500 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #15 -------------------------------#
#------------------------------------------------------------------------------#
# send it in on a port that's accepted.
echo -en "\n\n" >> $file
echo "Test Case: #15 - Accept all Fragments on allowed ports" >> $file
hping3 $FW_HOST -S -f -c $COUNT -p 80 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #16 -------------------------------#
#------------------------------------------------------------------------------#
# send it in on a port that's denied.
echo -en "\n\n" >> $file
echo "Test Case: #16 - Accept all Fragments on allowed ports" >> $file
echo "Note: This port specified is disallowed. Drop them." >> $file
hping3 $FW_HOST -S -f -c $COUNT -p 8080 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #17 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case #17 - Incoming TCP connection on permissible ports (SYN)" >> $file
hping3 $FW_HOST -S -c $COUNT -p 80 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #18 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #18 - Incoming TCP connection on permitted ports (non-SYN)" >> $file
echo "Note: This is a random, non-SYN packet. Drop these random packets." >> $file
hping3 $FW_HOST -F -c $COUNT -p 80 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #19 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #19 - Drop packets with SYN bits set" >> $file
echo "Note: This is on a bad port. Drop them." >> $file
hping3 $FW_HOST -S -c $COUNT -p 88 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #20 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #20 - Drop packets with FIN bits set" >> $file
hping3 $FW_HOST -F -c $COUNT -p 80 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #21 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #21 - Drop packets with SYN and FIN bits set" >> $file
hping3 $FW_HOST -S -F -c $COUNT -p 80 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #22 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #22 - Drop Telnet packets (internal)" >> $file
hping3 $INT_HOST -S -c $COUNT -p 23 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #24 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #24 - Drop Telnet packets (external)" >> $file
hping3 $INT_IF -S -c $COUNT -p 23 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #25 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #28 - Drop external traffic to specified ports" >> $file
echo "Target Host: Firewall - $FW_HOST" >> $file
hping3 $FW_HOST -S -c $COUNT -p 32768 >> $file 2>&1
hping3 $FW_HOST -S -c $COUNT -p 32775 >> $file 2>&1
hping3 $FW_HOST -S -c $COUNT -p 137 >> $file 2>&1
hping3 $FW_HOST -S -c $COUNT -p 139 >> $file 2>&1
hping3 $FW_HOST -S -c $COUNT -p 111 >> $file 2>&1
hping3 $FW_HOST -S -c $COUNT -p 515 >> $file 2>&1
hping3 $FW_HOST --udp -c $COUNT -p 32768 >> $file 2>&1
hping3 $FW_HOST --udp -c $COUNT -p 32775 >> $file 2>&1
hping3 $FW_HOST --udp -c $COUNT -p 137 >> $file 2>&1
hping3 $FW_HOST --udp -c $COUNT -p 139 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #27 -------------------------------#
#------------------------------------------------------------------------------#
# To be tested using alternate methods.
echo -en "\n\n" >> $file
echo "Test Case: #27 - Set control connections to Minimum Delay (SSH)" >> $file
echo "Note: To be tested using alternate methods. This is supplementary." >> $file
hping3 $FW_HOST -S -c $COUNT -p 22 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #28 -------------------------------#
#------------------------------------------------------------------------------#
# To be tested using alternate methods.
echo -en "\n\n" >> $file
echo "Test Case: #28 - Set control connections to Minimum Delay (FTP)" >> $file
echo "Note: To be tested using alternate methods. This is supplementary." >> $file
hping3 $FW_HOST -S -c $COUNT -p 20 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #29 -------------------------------#
#------------------------------------------------------------------------------#
# To be tested using alternate methods.
echo -en "\n\n" >> $file
echo "Test Case: #29 - Set control connections to Max. Throughput (FTP)" >> $file
echo "Note: To be tested using alternate methods." >> $file
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#---------------------------- END OF TESTING SCRIPT ---------------------------#
#------------------------------------------------------------------------------#
echo "Done testing firewall. Exiting..."
echo -en "\n\n" >> $file
echo "End of External Testing" >> $file
echo -en "\n" >> $file
