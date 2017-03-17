JFLAGS =
JC = javac
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
        Client.java \
        Server.java \
        ServerThread.java \
        GenCert.java \
		WrongPasswordException.java \
		KeyGen.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class