<h1>DNS-shell</h1>


<p>DNS-Shell is an interactive Shell over DNS channel. The server is Python based and can run on any operating system that has python installed, the payload is an encoded PowerShell command.</p>




<h2>Understanding DNS-Shell</h2>
<p>The Payload is generated when the sever script is invoked and it simply utilizes nslookup to perform the queries and query the server for new commands the server then listens on port 53 for incoming communications, once payload is executed on the target machine the server will spawn an interactive shell.</p>
<p>Once the channel is established the payload will continously query the server for commands if a new command is entered, it will execute it and return the result back to the server.</p>


<h2>Using DNS-Shell</h2>
<p>Running DNS-Shell is relatively simple</p>
<p>DNS-Shell supports two mode of operations direct and recursive modes:
<ul>
<li>Perform a git clone from our DNS-shell <a href="https://github.com/sensepost/DNS-Shell">Github page</a></li>
<li>DNS-Shell direct mode: sudo python DNS-Shell.py -l -d [Server IP]</li>
<li>DNS-Shell recursive mode: sudo python DNS-Shell.py -l -r [Domain]</li>
</ul>
<p>

