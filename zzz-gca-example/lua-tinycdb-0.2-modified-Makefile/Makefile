VERSION= 0.2

# ----------------------------------------------------------------------------------------
# modified Makefile for use with tinycdb and dnsdist - Seth - GlobalCyberAlliance - 5/15/2017
# ----------------------------------------------------------------------------------------

# change these to reflect your Lua installation
###LUA= /usr
###LUAINC= $(LUA)/include
###LUALIB= $(LUA)/lib
###LUABIN= $(LUA)/bin

# ----------------------------------------------------------------------------------------
# force using lua5.1 for use with tinycdb and dnsdist - Seth - GlobalCyberAlliance
# ----------------------------------------------------------------------------------------

LUA= /usr
LUAINC= $(LUA)/include/lua5.1
LUALIB= $(LUA)/lib/lua5.1
LUABIN= $(LUA)/bin/lua5.1

# ----------------------------------------------------------------------------------------
# added -fPIC to CFLAGS below for use with tinycdb and dnsdist - Seth - GlobalCyberAlliance
# ----------------------------------------------------------------------------------------

# probably no need to change anything below here
#
#
CC= gcc
CFLAGS= $(INCS) $(WARN) -O2 -fPIC
WARN= -Wall
INCS= -I$(LUAINC)

CDB_OBJS = cdb_init.o cdb_find.o cdb_findnext.o cdb_seq.o cdb_seek.o \
					 cdb_unpack.o \
					 cdb_make_add.o cdb_make_put.o cdb_make.o cdb_hash.o

OBJS=  $(CDB_OBJS) lcdb.o
SOS= cdb.so

all: $(SOS)

$(SOS): $(OBJS)
	$(CC) -o $@ -shared $(OBJS) $(LIBS)

.PHONY: clean test distr
clean:
	rm -f $(OBJS) $(SOS) core core.* a.out

test: all
	./lunit test.lua

tar: clean
	git archive --format=tar --prefix=lua-tinycdb-$(VERSION)/ $(VERSION) | gzip > lua-tinycdb-$(VERSION).tar.gz


