# RCS-Sniff-App

An app designed to automate the process of analyzing .cap files resulted from captures conducted on Android phones, through Wicap.
By scanning a capture, it should be able to detect and signal whenever one of the following events happen:

1. The intercepted phone is writing a RCS text message for a second phone
2. A second phone is writing a RCS text message intended for the intercepted phone
3. The intercepted phone sends a RCS text message to the second phone (the app should also detect the length of the message)
4. The intercepted phone receives a RCS text message from the second phone (the app should also detect the length of the message)
5. The intercepted phone has opened a RCS message from the second phone
6. The second phone has opened a RCS message from the intercepted phone
7. The intercepted phone has sent a RCS multimedia message to the second phone
8. The intercepted phone has received a RCS multimedia message from the second phone
9. The intercepted phone has received a shared location through RCS from the second phone
