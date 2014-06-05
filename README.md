# ring-secure-headers  [![Build Status](https://travis-ci.org/dhruvchandna/ring-secure-headers.png?branch=master)](https://travis-ci.org/dhruvchandna/ring-secure-headers)


Ring middleware to add secure headers to HTTP response. Inspired by [Twitter secureheaders](https://github.com/twitter/secureheaders)

## Installation
To include the library in your project include the following to your `:dependencies`:
	`[dhruv/ring-secure-headers "0.2.0"]`
    
## Usage
### Include all headers with default values
	(ns simple-ring-server.core
  	  (:use ring.middleware.secure-headers))
    
    (defn handler [request]
  		{:status 200
   		:headers {"Content-Type" "text/html"}
   		:body "Hello World"})

	(def app
    	(-> handler wrap-secure-headers))
        
## Default Values of Headers
#### X-Frame-Options
SAMEORIGIN
#### X-Content-Type-Options
nosniff
#### Strict-Transport-Security
max-age=31536000
#### X-XSS-Protection
1; mode=block

## License

Distributed under MIT license [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT)
