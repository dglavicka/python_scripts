# Cert Chain F5

  ## Licensing:
  [![license](https://img.shields.io/badge/license--blue)](https://shields.io)

  ## Table of Contents 
  - [Description](#description)
  - [Release Notes](#release-notes)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Testing](#testing)
  - [Additional Info](#additional-info)

  ## Description:
  Taken from https://github.com/jkolezyn/cert_tree and ported to work for F5 Load balancers
  
  ## Release Notes
  Attempted to port to python 2.7 to support F5 appliances \
  Adjusted length of certificate to 100 characters max due to column out \
  Ignore special characters or non english characters \
  Convert tree element to UTF8 for tree character support 
  
  ## Installation:
  scp file to F5 or paste with vi

  ## Usage:
  Run from F5 shell \
  python certchain.py </file/local/.pem> 
   - Command switches: \
     -p = show positon of cert in file as denoted in second column between brackets \
     -e = show certificate expiration dates denote in third column with EXPIRED or valid until \

  ## License:
   [![license](https://img.shields.io/badge/license--blue)](https://shields.io)

  ## Testing:
  F5 VE on 16.x firmware

  ## Additional Info:
  - Github: [dglavicka](https://github.com/dglavicka)
 
