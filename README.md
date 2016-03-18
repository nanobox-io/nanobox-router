#### TODO:
sort routes by most specific first   
  - adding path "/admin/" as well as "/" will only and always match "/"   
sort subdomains by most specific first   
  - adding subdomain.domain "admin.test.com" as well as "test.com" will only and always match "test.com"   
allow matching with no path (default to "/")   
  - currently matching with domain only fails   
