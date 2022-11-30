![](https://dev.lutece.paris.fr/jenkins/buildStatus/icon?job=tech-library-signrequest-deploy)
[![Alerte](https://dev.lutece.paris.fr/sonar/api/project_badges/measure?project=fr.paris.lutece.plugins%3Alibrary-signrequest&metric=alert_status)](https://dev.lutece.paris.fr/sonar/dashboard?id=fr.paris.lutece.plugins%3Alibrary-signrequest)
[![Line of code](https://dev.lutece.paris.fr/sonar/api/project_badges/measure?project=fr.paris.lutece.plugins%3Alibrary-signrequest&metric=ncloc)](https://dev.lutece.paris.fr/sonar/dashboard?id=fr.paris.lutece.plugins%3Alibrary-signrequest)
[![Coverage](https://dev.lutece.paris.fr/sonar/api/project_badges/measure?project=fr.paris.lutece.plugins%3Alibrary-signrequest&metric=coverage)](https://dev.lutece.paris.fr/sonar/dashboard?id=fr.paris.lutece.plugins%3Alibrary-signrequest)

# Library SignRequest

## Introduction

The purpose of this library is to provide a number of tools and interfaces to send HTTP requests with digital signatures to ensurea certain level of security.

## Security provided by a signature

The security provided by a signature associated OF a HTTP request is very useful in the context of REST webservice where there is no concept of session (stateless mode - without state).

The principle of the signature is to achieve a client-side condensate (hash) of a certain element the query variables (parameters), a timestamp (to limit the validity of the signature in time)and a secret key (known as client and server). This condensate is obtained using a hash algorithm (SHA-1, SHA-256, ...) and isactual signature of the query. It comes in the form of a string representing a number in hexadecimal.

The signature is transmitted to the server, which will restore a condensate on its side with its secret key. If the signature is properly restored, the request is valid, otherwise she refused with a 401 HTTP status code.

This is what brings the signature in terms of safety:
 
* An HTTP request or a WebService call can be executed by a customer who does not have the secret key
* If the Timestamp option control is enabled, the request has a life limited in time. It is not possible to replay the request within that period.
* Validate the integrity of parameters passed (if they are part of the signature).


Here's what the signature does not in terms of safety:


 
* The confidentiality of data transmitted. This can be achieved by encrypting the transmission with HTTPS
* The ability to replay exactementla same query in a limited time.
* The simple signature is not related to a user thus does not allow management of access rights. To validate a signature by user, it isnecessary to rely on a server identity (Identity Provider) using protocols like OAuth.


In summary, the security offered by the signature mechanism corresponds to operation without a need for session typically REST Webservices.It is well suited for securing between two servers where requests from a very small population of users (confidentiality of the shared secret) orwithout access to the secret key.

To ensure data privacy, data transfer must be achieved by HTTPS.

# Tools provided by SignRequest

## API RequestAuthenticator

API `RequestAuthenticator` : defines a Authenticator HTTP request.

The same component can be used client side to sign a petition and server side to validate authentication.Here is the interface and two methods to implement:


```

                            / **
                            * Check the Authentication of a request
                            * @ Param request The HTTP request
                            * @ Return true if authenticated, false Otherwise
                            * /
                            boolean  ** isRequestAuthenticated **  (HttpServletRequest request);

                            / **
                            * return Security informations to put in the request headers and request parameters
                            * @ Param elements List of elements to include in the signature
                            * /
                            AuthenticateRequestInformations   ** getSecurityInformations **  ( List elements);
                        
                        
```


This interface offers many implementations. A good practice is to inject a Spring context via the implementationdesired.The library offers several implementations SignRequest:


 
* NoSecurityAuthenticator: no authentication control
* HeaderHashAuthenticator: Signature passed in a header of the HTTP request
* RequestHashAuthenticator: Signature spent in a header of the HTTP request


## RequestHashAuthenticator and HeaderHashAuthenticator

These authenticators must be configured using several parameters:


 
* service hash. The library provides an API SignRequest HashService and an implementation using the SHA-1.
* the private key corresponding to the shared secret between client and server
* list of query parameters that are used to compose the signature
* the validity of the signature in seconds. The value 0 indicates that the duration is not controlled.

Configuring a RequestAuthenticator in the REST plugin
Securing all requests can be made at the REST plugin by injecting a Spring context via the authenticator.

By default the plugin uses REST implementation `NoSecurityRequestAuthenticator` which allows all queries. The example below shows a configuration HeaderHashRequestAuthenticator using the setup and specific.
<bean id="rest.hashService" class="fr.paris.lutece.util.signrequest.security.Sha1HashService" /><bean id="rest.requestAuthenticator" class="fr.paris.lutece.util.signrequest.HeaderHashAuthenticator"><property name="hashService" ref="rest.hashService" /><property name="signatureElements"><list><value>key</value></list></property><property name="privateKey"><value>change me</value></property><property name="validityTimePeriod"><value>0</value></property></bean>
# API HashService

Cette API propose une fonction de hachage

Voici l'interface


```

                        /**
                        * Create a Hash string from a given source
                        * @param strSource The source
                        * @return The Hash
                        */
                        String getHash( String strSource );
        
                    
```


The library offers SignRequest implementing SHA-1.

# Servlet Filters

The library also offers SignRequest Servlet filters that can be used by plugins in order to validatequeries on the server side.They are based on authenticators provided with the library.An example of a filter added to the XML file of a plugin:


```

<filters>
       <filter>
           <filter-name>myresourcesecurity</filter-name>
           <url-pattern>/rest/myresource/*</url-pattern>
           <filter-class>fr.paris.lutece.util.signrequest.servlet.HeaderHashRequestFilter</filter-class>

           <init-param>
               <param-name>elementsSignature</param-name>
               <param-value>id-resource,name,description</param-value>
           </init-param>

           <init-param>
               <param-name>validityTimePeriod</param-name>
               <param-value>0</param-value>
           </init-param>

           <init-param>
               <param-name>privateKey</param-name>
               <param-value>change me</param-value>
           </init-param>
       </filter>
   </filters>
                    
```



[Maven documentation and reports](https://dev.lutece.paris.fr/plugins/library-signrequest/)



 *generated by [xdoc2md](https://github.com/lutece-platform/tools-maven-xdoc2md-plugin) - do not edit directly.*