#Script to launch several Servers simultaneously

serverNmbr=10
for (( i=0; i <= $serverNmbr; ++i ))
do
	java Server
done
