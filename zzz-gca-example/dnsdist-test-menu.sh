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

test_bind(){
	CFG_FILE="dnsdist-named-cache-test-3-bind.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}
 

test_load(){
	CFG_FILE="dnsdist-named-cache-test-3-load.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}
 

test_load_debug(){
	CFG_FILE="dnsdist-named-cache-test-3-load-debug.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}

test_bind_spoof(){
	CFG_FILE="dnsdist-named-cache-test-3-spoof-bind.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}

test_load_spoof(){
	CFG_FILE="dnsdist-named-cache-test-3-spoof-load.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}

test_load_spoof_slow(){
	CFG_FILE="dnsdist-named-cache-test-3-spoof-load-slow.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}

test_load_spoof_release(){
	CFG_FILE="dnsdist-named-cache-test-3-spoof-load-release-ram.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}

test_load_spoof_seth(){
	CFG_FILE="dnsdist-named-cache-test-3-alt-spoof-load.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}

test_original_complex(){
	CFG_FILE="dnsdist-complex.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}

test_original_simple(){
	CFG_FILE="dnsdist-simple.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}


test_load_spoof_walk_right_to_left(){
	CFG_FILE="dnsdist-named-cache-test-3-spoof-load-walk-right.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}


test_load_spoof_walk_left_to_right(){
	CFG_FILE="dnsdist-named-cache-test-3-spoof-load-walk-left.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}

test_load_spoof_walk_right_to_left_alt(){
	CFG_FILE="dnsdist-named-cache-test-3-spoof-load-walk-right-alt.conf"
	CONFIG_FILE=$DIR$SLASH$CFG_FILE
	echo "current directory: " $DIR
	echo ""
	echo "configuration file: " $CONFIG_FILE
	echo ""

	./dnsdist --config=$CONFIG_FILE
        pause
}

# function to display menus
show_menus() {
	clear
	echo "~~~~~~~~~~~~~~~~~~~~~"	
	echo " dnsdist named cache test configurations"
	echo "~~~~~~~~~~~~~~~~~~~~~"
	echo "1. bindToCDB()"
	echo "2. loadFromCDB()"
	echo "3. bindToCDB()   with spoofing response"
	echo "4. loadFromCDB() with spoofing response"
	echo "5. loadFromCDB() with spoofing response and slow loading"
	echo "6. loadFromCDB() with spoofing response and forced memory release to os"
	echo "7. loadFromCDB() with spoofing response - Seth's protobuf method using RemoteLogActionX"
	echo "8. non-named cache lua access of cdb"
	echo "9. simple demo of lua config - no cdb, only reject entry is 1jw2mr4fmky.net, else forward to dns"
	echo "a. loadFromCDB() - debug"
	echo "b. loadFromCDB() with spoofing response and dns walking - right to left"
	echo "c. loadFromCDB() with spoofing response and dns walking - left to right"
	echo "d. loadFromCDB() with spoofing response and dns walking - right to left - alternate"
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
		1) test_bind ;;
		2) test_load ;;
		3) test_bind_spoof ;;
		4) test_load_spoof ;;
		5) test_load_spoof_slow ;;
		6) test_load_spoof_release ;;
		7) test_load_spoof_seth ;;
		8) test_original_complex ;;
		9) test_original_simple ;;
		0) exit 0;;
		a) test_load_debug ;;
		b) test_load_spoof_walk_right_to_left ;;
		c) test_load_spoof_walk_left_to_right ;;
		d) test_load_spoof_walk_right_to_left_alt ;;
		*) echo -e "${RED}Error...${STD}" && sleep 2
	esac
}
 
setup_stuff() {
	DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
	SLASH="/"
	echo "cd ../pdns/dnsdistdist"
	echo ""
	cd ../pdns/dnsdistdist
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
