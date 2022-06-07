JAVAC=/usr/bin/javac
.SUFFIXES: .java .class

SRCDIR=src
BINDIR=bin
CLASSPATH=".:lib/*:$(BINDIR)"

SRCDIRX=./src
DOCDIR=./java_doc
SOURCELIST=$(shell find $(SRCDIRX) -name '*.java' | sed "s,[.]/,,g")

$(BINDIR)/%.class:$(SRCDIR)/%.java
	$(JAVAC) -d $(BINDIR)/ -cp $(CLASSPATH) $<

CLASSES = clientObj.class senderThread.class receiverThread.class udpClient.class udpServer.class udpDriver.class
CLASS_FILES=$(CLASSES:%.class=$(BINDIR)/%.class)

default: $(CLASS_FILES)

clean:
	rm $(BINDIR)/*.class
	@if [ -d $(DOCDIR) ]; then rm -r $(DOCDIR); fi;
	
runServerWAN:
	@java -cp $(CLASSPATH) udpDriver "sWan" "false"
		
runServerLOCAL:
	@java -cp $(CLASSPATH) udpDriver "sLocal" "false"
	
runClientWAN:
	@java -cp $(CLASSPATH)udpDriver "cWan" "false"

runClientWAN_debug:
	@java -cp $(CLASSPATH)udpDriver "cWan" "true"

runClientLOCAL:
	@java -cp $(CLASSPATH) udpDriver "cLocal" "false"

runClientLOCAL_debug:
	@java -cp $(CLASSPATH) udpDriver "cLocal" "true"
	
runJavaDoc:
	@javadoc -cp $(CLASSPATH) -d $(DOCDIR) -linksource $(SOURCELIST)