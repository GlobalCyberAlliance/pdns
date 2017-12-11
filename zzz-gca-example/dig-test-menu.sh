#!/bin/bash
# A menu driven shell script sample template 
## ----------------------------------
# Step #1: Define variables
# ----------------------------------
EDITOR=vim
PASSWD=/etc/passwd
RED='\033[0;41;30m'
STD='\033[0;0;39m'
 
# ----------------------------------
# Step #2: User defined function
# ----------------------------------
pause(){
  read -p "Press [Enter] key to continue..." fackEnterKey
}

dig_test_nocookie(){
	./dig-test-nocookie.sh
        pause
}
 
dig_test_nocookie2(){
	./dig-test-nocookie2.sh
        pause
}

dig_test_rpz(){
	./dig-test-rpz.sh
        pause
}

dig_test_rpz_uppercase(){
	./dig-test-rpz-uppercase.sh
        pause
}

dig_test_rpz_spoof(){
	./dig-test-rpz-spoof.sh
        pause
}


dig_test_rpz_walk(){
	./dig-test-rpz-walk.sh
        pause
}

dig_test_rpz_walk2(){
	./dig-test-rpz-walk2.sh
        pause
}

# function to display menus
show_menus() {
	clear
	echo "~~~~~~~~~~~~~~~~~~~~~"	
	echo " dnsdist named cache test configurations"
	echo "~~~~~~~~~~~~~~~~~~~~~"
	echo "1. dig-test-nocookie()"
	echo "2. dig-test-nocookie2()"
	echo "3. dig-test-rpz()"
	echo "4. dig-test-rpz-uppercase()"
	echo "5. dig-test-rpz-spoof()"
	echo "6. dig-test-rpz-walk()"
	echo "7. dig-test-rpz-walk2()"
	echo "0. Exit"
}
# read input from the keyboard and take a action
# invoke the one() when the user select 1 from the menu option.
# invoke the two() when the user select 2 from the menu option.
# Exit when user the user select 3 form the menu option.
read_options(){
	local choice
	read -p "Enter choice [#] " choice
	case $choice in
		1) dig_test_nocookie ;;
		2) dig_test_nocookie2 ;;
		3) dig_test_rpz ;;
		4) dig_test_rpz_uppercase ;;
		5) dig_test_rpz_spoof ;;
		6) dig_test_rpz_walk ;;
		7) dig_test_rpz_walk2 ;;
		0) exit 0;;
		*) echo -e "${RED}Error...${STD}" && sleep 2
	esac
}
 
setup_stuff() {
	echo ""
}

# ----------------------------------------------
# Step #3: Trap CTRL+C, CTRL+Z and quit singles
# ----------------------------------------------
trap '' SIGINT SIGQUIT SIGTSTP
 
# -----------------------------------
# Step #4: Main logic - infinite loop
# ------------------------------------
	setup_stuff
while true
do
 
	show_menus
	read_options
done
