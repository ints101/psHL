param (
    [string]$baseurl,
    [string]$wl,
    [string]$method,
    [string]$data,
    [string]$extension,
    [string]$proxy, 
    [switch]$subdm,
    [int]$MaximumRedirection,
    [string]$fs
)

# Convert HTTP method to uppercase
$method = $method.ToUpper()

# Check if the base URL is empty
if ($baseurl -eq "") {
    Write-Host "Please enter a URL"
    return
}

# Add trailing forward slash to URL if missing
if (($baseurl -notmatch '/$') -and ($baseurl -ne "") -and ($subdm -ne $true)) {
    $baseurl += "/"
}

# Add 'http://' if missing
if (($baseurl -ne "") -and ($baseurl -notmatch '^http://|^https://')) {
    $baseurl = "http://$baseurl"
}

# Add leading dot to the extension if missing
if (($extension -notmatch '^\.') -and ($extension -ne "")) {
    $extension = "." + $extension
}

# Color mapping for output
$colorMapping = @{
    "2xx" = "Green"
    "3xx" = "Magenta"
    "4xx" = "Yellow"
    "5xx" = "Red"
    "Other" = "White"
}

# Function to get color based on status code
function GetColor($statusCode) {
    switch ($statusCode) {
        { $_ -ge 200 -and $_ -lt 300 } { return $colorMapping["2xx"] }
        { $_ -ge 300 -and $_ -le 399 } { return $colorMapping["3xx"] }
        { $_ -ge 400 -and $_ -lt 500 } { return $colorMapping["4xx"] }
        { $_ -ge 500 }                 { return $colorMapping["5xx"] }
        default                        { return $colorMapping["Other"] }
    }
}

# Set default method to GET if not specified
if ($method -eq "") {
    $method = "GET"
    Write-Host "No HTTP method specified, using 'GET'."
}

#Disable $data if method doesn't support it
if ($method -ieq "GET" -or  $method -ieq "HEAD" -or $method -ieq "TRACE" -or $method -ieq "CONNECT" -or $method -ieq "OPTIONS" -or $method -ieq "DELETE") {
    $data = $null
}

# Read the wordlist and filter out empty lines
try {
    $wordlist = Get-Content $wl | Where-Object { $_.Trim() -ne "" }
}
catch {
    Write-Output "Something wrong with the wordlist. Did you use '-wl /PATH/TO/WORDLISTFILE'?"
    return
}

$runonce = $false

#Arrays for results
$results2xx = @('Found the following pages with a status code 2xx:')
$results3xx = @('Found the following pages with a status code 3xx:')
$results4xx = @('Found the following pages with a status code 4xx:')
$results5xx = @('Found the following pages with a status code 5xx:')


# Main logic based on data input
foreach ($line in $wordlist) {

    # Extract prefix from URL
    $httpPrefix = $baseurl.Substring(4, 1)

    # Create URL for subdomain enumeration
    if ($subdm) {
        switch ($httpPrefix) {
            ":" {
                $requestedUrl = "$line.$baseurl".Replace("http://", "")
                $requestedUrl = "http://$requestedUrl"
            }
            "s" {
                $requestedUrl = "$line.$baseurl".Replace("https://", "")
                $requestedUrl = "https://$requestedUrl"
            }
        }

        # Display message only once for subdomain enumeration
        if (-not $runonce) {
            Write-Host "Enumerating subdomains!"
            $runonce = $true
        }
    }
    # Create the URL string for directory and webpage fuzzing
    else {
        $requestedUrl = "$baseurl$line$extension"
    }

    #Doin some splatting
    $requestParams = @{
        Uri                  = $requestedUrl
        Method               = $method
        ErrorAction          = 'Ignore'
    }


    #Checking params and adding to the hash table
    if ($data -ne "") {
        $requestParams['Body'] = $data
        }

    if ($proxy -ne "") {
        $requestParams['Proxy'] = $proxy
    }
    
    if ($MaximumRedirection -eq "") {
        $requestParams['MaximumRedirection'] = '0'
    }     
    else {
        $requestParams['MaximumRedirection'] = $MaximumRedirection
    }


    

if ($PSVersiontable.PSVersion.Major -lt 6) {
    # Try to make the web request
    try { 
        $response = Invoke-WebRequest @requestParams

        #Get status code
        $StatusCode = $response.Statuscode

        #Try to extract status code from the raw content if previous step fails
        if ($StatusCode -eq "" ) {
        $response2 = (Invoke-WebRequest @requestParams).RawContent
        $StatusCode = [regex]::Match($response2, 'HTTP/\d+(\.\d+)?\s+(\d{3})').Groups[2].Value
        }

        #Read Content-Length header
        $ContentLen = $response.Headers["Content-Length"]

        #If there's no header ,read from response
        if ($ContentLen -eq $null -or $ContentLen -eq "") {
            $ContentLen = $response.Content.Length

        #Fuckit, just give up
         if ($ContentLen -eq "" -or $ContentLen -eq $null) {
            $ContentLen = "N/A"
            }
         }
        
         

        #Set color and print output
        $color = GetColor $StatusCode
        Write-Host "Method: $method  | Status Code: $StatusCode | Content Length: $ContentLen | Requested URL: $requestedUrl  "-ForegroundColor $color
        Write-Output ""

        #Saving the results
        if ($StatusCode -ge 200 -and $StatusCode -lt 300) {
            $results2xx += $requestedUrl
        }

        if ($StatusCode -ge 300 -and $StatusCode -lt 400) {
            $results3xx += $requestedUrl
        }

        #Have to reset the variable. Don't know why
        $ContentLen = $null
        

    }
    catch {
        #Get the status code from exception response
        $StatusCode = $_.Exception.Response.StatusCode.Value__

        #Give up if unsuccesful
        if ($StatusCode -eq "" -or $StatusCode -eq $null) {
            $StatusCode = "N/A"
            }

        #Getting the content length from error response stream
        if ($_.Exception.Response -ne $null -and $_.Exception.Response.GetResponseStream() -ne $null) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseContent = $reader.ReadToEnd()
        $ContentLen = $responseContent.Length
        }

        #Give up if unsuccesful
        if ($ContentLen -eq "" -or $ContentLen -eq $null) {
            $ContentLen = "N/A"
            }

        #Saving the results
        if ($StatusCode -ge 300 -and $StatusCode -lt 400) {
            $results3xx += $requestedUrl
        }

        if ($StatusCode -ge 400 -and $StatusCode -lt 500) {
            $results4xx += $requestedUrl
        }

         if ($StatusCode -ge 500 -and $StatusCode -lt 600) {
            $results5xx += $requestedUrl
        }

        

        #Set color and print output
        $color = GetColor $StatusCode
        Write-Host "Method: $method | Status Code: $StatusCode | Content Length: $ContentLen | Requested URL: $requestedUrl" -ForegroundColor $color
        Write-Output ""
    }
}




if ($PSVersiontable.PSVersion.Major -ge 6) {
    try {

        #Using SkipHttpErrorCheck. Try block should handle all responses. Even error codes.
        if ($PSVersiontable.PSVersion.Major -ge 7){
         $response = Invoke-WebRequest @requestParams -SkipCertificateCheck -SkipHttpErrorCheck
         }
         #If PS version does not support SkipHttpErrorCheck, skippidy skip the cert check only
         else {
         $response = Invoke-WebRequest @requestParams -SkipCertificateCheck
         }

        #Get status code
        $StatusCode = $response.StatusCode

        #Try to extract status code from the raw content if all else fails
        if ($StatusCode -eq "" ) {
        $response2 = (Invoke-WebRequest @requestParams).RawContent
        $StatusCode = [regex]::Match($response2, 'HTTP/\d+(\.\d+)?\s+(\d{3})').Groups[2].Value
        }

         $color = GetColor $StatusCode

        #Saving the results
        if ($StatusCode -ge 200 -and $StatusCode -lt 300) {
            $results2xx += $requestedUrl
        }
        if ($StatusCode -ge 300 -and $StatusCode -lt 400) {
            $results3xx += $requestedUrl
        }
        if ($StatusCode -ge 400 -and $StatusCode -lt 500) {
            $results4xx += $requestedUrl
        }
        if ($StatusCode -ge 500 -and $StatusCode -lt 600) {
            $results5xx += $requestedUrl
        }
        
         $ContentLen = $response.Headers["Content-Length"]

         if ($ContentLen -eq $null -or $ContentLen -eq "") {
            $ContentLen = $response.Content.Length
            }

         Write-Host "Method: $method | Status Code: $StatusCode | Content Length: $ContentLen | Requested URL: $requestedUrl " -ForegroundColor $color
         Write-Output ""
         $ContentLen = $null
    } 
    catch {
        #Get the status code from exception response
        $StatusCode = $_.Exception.Response.StatusCode.Value__

        #Give up if unsuccesful
        if ($StatusCode -eq "" -or $StatusCode -eq $null) {
            $StatusCode = "N/A"
            }

        #Getting the content length from error response stream
        if ($_.Exception.Response -ne $null -and $_.Exception.Response.GetResponseStream() -ne $null) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseContent = $reader.ReadToEnd()
        $ContentLen = $responseContent.Length
        }

        #Give up if unsuccesful
        if ($ContentLen -eq "" -or $ContentLen -eq $null) {
            $ContentLen = "N/A"
            }


        #Saving the results
        if ($StatusCode -ge 300 -and $StatusCode -lt 400) {
            $results3xx += $requestedUrl
        }

        if ($StatusCode -ge 400 -and $StatusCode -lt 500) {
            $results4xx += $requestedUrl
        }

         if ($StatusCode -ge 500 -and $StatusCode -lt 600) {
            $results5xx += $requestedUrl
        }

        

        #Set color and print output
        $color = GetColor $StatusCode
        Write-Host "Method: $method | Status Code: $StatusCode | Content Length: $ContentLen | Requested URL: $requestedUrl" -ForegroundColor $color
        Write-Output ""
    }
}
}

#Split and write -fs arguments to array.
$fsArray = $fs -split " "
foreach ($statusCode in $fsArray) {

#Print out results
switch ($statusCode.Trim()) {
    "2xx" {
        foreach ($url in $results2xx) { 
        Write-Output $url
        Write-Output ""
    }
    }
    "3xx" {
        foreach ($url in $results3xx) {
        Write-Output $url
        Write-Output ""
    }
    }
    "4xx" {
        foreach ($url in $results4xx) {
        Write-Output $url
        Write-Output ""
    }
    }
    "5xx" {
        foreach ($url in $results5xx) {
        Write-Output $url
        Write-Output ""
    }
    }
 }  
}

