 PshlFzzr is a very simple web fuzzing script for those awkward moments <br>
 when You need to use Powershell to scan a Web server.<br>
 It's a loop that uses the Invoke-WebRequest cmdlet to send HTTP requests.<br>
 You can use a wordlist to fuzz Web directories, pages, or subdomains. There is no recursion.<br>
 Tested on Powershell 5 and 7. Doesn't seem to work in Powershell 6.<br>
 Takes the following arguments:<br>
<br>
<br>
 <h2>Required:</h2>
<em>-wl</em><br>                  Path to the wordlist     <code>-wl /PATH/TO/WORDLIST</code><br>
<br>
<em>-baseurl</em><br>             Url to scan              <code>-baseurl example.com</code><br>
<br>
<br>
<h2>Optional:</h2><br>
<em>-subdm</em><br> 
Runs a subdomain scan    <code>-subdm</code><br>
<br>
<em>-method</em><br>            HTTP method to use. Supports Delete, Get, Head, Merge, Options, Patch, Post, Put, Trace. Default is Get.   <code>-method put</code><br>
<br>
<em>-extension</em><br>         File extension to use                                                                                       <code>-extension .php</code><br>
<br>
<em>-fs</em><br>                  Prints out results at the end of the run sorted by status code ranges(2xx, 3xx, 4xx, 5xx)                 <code>-fs 2xx, 3xx</code><br>
<br>
<em>-proxy</em><br>               Web proxy address                                                                                          <code>-proxy http://127.0.0.1:8080</code><br>
<br>
<em>-MaximumRedirection</em><br>  Maximum number of redirections. Default is 0. Maximum is 5.                                                <code>-MaximumRedirection 1</code><br>
<br>
<em>-data</em><br>                Data to send in the body of the request. Disabled if the method doesn't support it.                        <code>-data "user=stpd&password=lkeafx"</code><br>
<br>

![2024-10-26_03-26](https://github.com/user-attachments/assets/fd5d44e1-2c56-430e-bd6e-31d3b38fde09)
<br>
<br>
![2024-10-26_03-27](https://github.com/user-attachments/assets/2550d01b-9508-4518-97b8-afe9048e7cbe)
