#
# Makefile
#

all: glacier_util.jar

glacier_util.jar: glacier_util.java
	javac $^
	jar cef glacier_util $@ *.class
