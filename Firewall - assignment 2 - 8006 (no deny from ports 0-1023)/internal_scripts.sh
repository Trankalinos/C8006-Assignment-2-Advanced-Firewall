################################################################################
#------------------------------------------------------------------------------#
#
#	Filename: 	internal_scripts.sh
#
#	Authors:	David Tran - A00801942 
#			Cole Rees  - A00741578
#
#	Date:		Thursday, February 20 2014
#
#	Usage:		./internal_scripts.sh
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
#			This script shall be ran on the internal host of our
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

ALLOWED_TCP=('80' '443' '22' '20')			# array, to loop through
ALLOWED_UDP=('53' '67' '68')				# array, to loop through

DISALLOWED_TCP=('8080' '4434' '222' '212' '252')	# array, to loop through
DISALLOWED_UDP=('534' '678' '689')			# array, to loop through

COUNT="5"
file="./int-test-results.txt"

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
#-------------------------------- Test Case # 3 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #3 - In / Out TCP allowed on specified ports" >> $file
for i in "${ALLOWED_TCP[@]}"
do
	hping3 $INT_IF -S -c $COUNT -p $i >> $file 2>&1
	echo -en "\n" >> $file
done
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case # 4 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #4 - In / Out TCP allowed on specified ports" >> $file
for i in "${DISALLOWED_TCP[@]}"
do
	hping3 $INT_IF -S -c $COUNT -p $i >> $file 2>&1
	echo -en "\n" >> $file
done
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case # 5 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #5 - In / Out UDP allowed on specified ports" >> $file
for i in "${ALLOWED_UDP[@]}"
do
	hping3 $INT_IF --udp -c $COUNT -p $i >> $file 2>&1
	echo -en "\n" >> $file
done
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case # 6 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #6 - In / Out UDP allowed on specified ports" >> $file
for i in "${DISALLOWED_UDP[@]}"
do
	hping3 $INT_IF --udp -c $COUNT -p $i >> $file 2>&1
	echo -en "\n" >> $file
done
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case # 7 -------------------------------#
#------------------------------------------------------------------------------#

# Test Case 7: ICMP accepts
echo -en "\n\n" >> $file
echo "Test Case: #7 - ICMP (expected accepts)" >> $file
ping $INT_IF -c $COUNT >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #12 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #12 - Drop all packets pretending to be internal host" >> $file
echo "Note: This is a real internal host. Accept them." >> $file
hping3 $INT_IF -S -p 80 -c $COUNT -a $INT_HOST >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #23 -------------------------------#
#------------------------------------------------------------------------------#
echo -en "\n\n" >> $file
echo "Test Case: #23 - Internal outgoing telnet packets dropped" >> $file
hping3 $INT_IF -S -c $COUNT -a $INT_IF -p 23 >> $file 2>&1
hping3 $INT_IF -S -c $COUNT -a 192.168.0.24 -p 23 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#-------------------------------- Test Case #26 -------------------------------#
#------------------------------------------------------------------------------#

# Drop external packets to specific ports.
echo -en "\n\n" >> $file
echo "Test Case: #26 - Drop external packets to specific ports" >> $file
echo "Target Host: Internal - $INT_IF" >> $file
hping3 $INT_IF -S -c $COUNT -p 32768 >> $file 2>&1
hping3 $INT_IF -S -c $COUNT -p 32775 >> $file 2>&1
hping3 $INT_IF -S -c $COUNT -p 137 >> $file 2>&1
hping3 $INT_IF -S -c $COUNT -p 139 >> $file 2>&1
hping3 $INT_IF -S -c $COUNT -p 111 >> $file 2>&1
hping3 $INT_IF -S -c $COUNT -p 515 >> $file 2>&1
hping3 $INT_IF --udp -c $COUNT -p 32768 >> $file 2>&1
hping3 $INT_IF --udp -c $COUNT -p 32775 >> $file 2>&1
hping3 $INT_IF --udp -c $COUNT -p 137 >> $file 2>&1
hping3 $INT_IF --udp -c $COUNT -p 139 >> $file 2>&1
echo -en "\n" >> $file

#------------------------------------------------------------------------------#
#---------------------------- END OF TESTING SCRIPT ---------------------------#
#------------------------------------------------------------------------------#
echo "Done testing internally..."
echo -en "\n\n" >> $file
echo "End of internal test script..." >> $file
echo -en "\n" >> $file
