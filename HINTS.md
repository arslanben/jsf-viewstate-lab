# Hints

Read one at a time. Each assumes you have worked through the previous ones.

1. Submit the login form and watch the traffic. One hidden field is sent on every request,
   and its value changes on every page load.

2. That field is Base64. Decode it, notice the GZIP magic bytes, decompress it. You are
   looking at a Java serialization stream.

3. Now break it on purpose: post the ViewState replaced with (a) random garbage,
   (b) a truncated serialization stream, (c) a valid stream naming a class that does not
   exist. Three different Java errors come back — each one proves a link in the chain
   Base64 -> GZIP -> ObjectInputStream.readObject(), running before login ever happens.

4. The server has to turn that blob back into objects on every postback. What does that
   imply for a value the client can replace entirely, and when in the request lifecycle
   does that conversion happen?

5. Enumerate the libraries shipped with the application (the `WEB-INF/lib` directory, error
   pages, dependency fingerprints). One of them is a classic gadget dependency.

6. The chain does not need a known-vulnerable framework class; it needs a class that can
   load attacker-supplied bytecode. Public chains for these libraries exist, and ysoserial
   ships one for exactly this combination.

7. The container has no outbound connectivity, so reverse shells and DNS callbacks will not
   work. But the directory the web application is deployed from is writable by the process
   that runs it, and Tomcat serves files from there.
