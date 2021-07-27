# RCS-Sniff-App

An app designed to automate the process of analyzing .cap files resulted from captures conducted on Android phones, through Wicap.
By scanning a capture, it should be able to detect and signal whenever one of the following events happen:

1. The intercepted phone is writing a RCS message for a second phone
2. A second phone is writing a RCS message intended for the intercepted phone
3. The intercepted phone sends a message to the second phone (the app should also detect the length of the message)
4. The intercepted phone has opened a message from the second phone
